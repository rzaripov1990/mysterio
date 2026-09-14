package proxy

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/testme"
	"mysterio/internal/token"
)

// backendKind selects how a reverse proxy rewrites the upstream path and how
// its responses are masked.
type backendKind int

const (
	backendLoki backendKind = iota
	backendElastic
	backendGraphQL
)

func NewHandler(cfg config.Config, m *masker.Masker) (http.Handler, error) {
	if !cfg.LokiEnabled && !cfg.ElasticEnabled && !cfg.GraphQLEnabled {
		return nil, fmt.Errorf("no backend enabled: set LOKI_ENABLED, ELASTIC_ENABLED and/or GRAPHQL_ENABLED")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	if cfg.LokiEnabled {
		rp, err := newReverseProxy(cfg.LokiURL, cfg, m, backendLoki, GraphQLMaskers{})
		if err != nil {
			return nil, fmt.Errorf("loki upstream: %w", err)
		}
		mux.Handle("/loki/", http.StripPrefix("/loki", rp))
	}

	if cfg.ElasticEnabled {
		rp, err := newReverseProxy(cfg.ElasticURL, cfg, m, backendElastic, GraphQLMaskers{})
		if err != nil {
			return nil, fmt.Errorf("elastic upstream: %w", err)
		}
		mux.Handle("/elastic/", http.StripPrefix("/elastic", rp))
	}

	if cfg.GraphQLEnabled {
		// The /graphql route masks with the rules file's graphql block only —
		// it REPLACES the global json_keys/regex rather than extending them.
		gqlMasker, err := masker.NewGraphQL(cfg.Rules.GraphQL.JSONKeys, processTokenizer(cfg))
		if err != nil {
			return nil, fmt.Errorf("graphql masker: %w", err)
		}
		rp, err := newReverseProxy(cfg.GraphQLURL, cfg, nil, backendGraphQL, GraphQLMaskers{Doc: gqlMasker, Text: m})
		if err != nil {
			return nil, fmt.Errorf("graphql upstream: %w", err)
		}
		mux.Handle("/graphql", rp)
		mux.Handle("/graphql/", rp)
		slog.Info("graphql masking rules",
			"rules_path", cfg.RulesPath,
			"keys", graphQLRuleKeys(cfg.Rules.GraphQL.JSONKeys),
		)
	}

	if cfg.TestMeEnabled {
		tm := testme.NewHandler(cfg.BasePath, cfg.RawRulesYAML, processTokenizer(cfg))
		mux.Handle("/test-me", tm)
		mux.Handle("/test-me/", tm)
	}

	return withLogging(mux), nil
}

// processTokenizer returns the process HMAC tokenizer, or nil when
// MASK_HMAC_KEY is unset. masker.New rejects {hmac} rules with a nil
// tokenizer, so a misconfiguration fails at startup rather than silently
// falling back to "***".
func processTokenizer(cfg config.Config) *token.Tokenizer {
	if len(cfg.MaskHMACKey) == 0 {
		return nil
	}
	return token.New(cfg.MaskHMACKey)
}

// m masks the log backends (Loki, Elastic); gql masks backendGraphQL. Each
// kind uses only its own and ignores the other.
func newReverseProxy(rawUpstream string, cfg config.Config, m *masker.Masker, kind backendKind, gql GraphQLMaskers) (*httputil.ReverseProxy, error) {
	upstream, err := url.Parse(rawUpstream)
	if err != nil {
		return nil, err
	}

	// For Loki, keep path prefix from LOKI_URL (e.g. https://host/loki) separately and
	// drive the reverse proxy off the host root. Grafana may call either
	// /loki/api/v1/... or /loki/loki/api/v1/... depending on datasource URL/version;
	// after StripPrefix("/loki") those become /api/v1/... or /loki/api/v1/..., and we
	// normalize to what the upstream actually serves.
	pathPrefix := ""
	proxyTarget := upstream
	if kind == backendLoki {
		pathPrefix = strings.TrimSuffix(upstream.Path, "/")
		base := *upstream
		base.Path = ""
		base.RawPath = ""
		proxyTarget = &base
	}

	rp := httputil.NewSingleHostReverseProxy(proxyTarget)
	rp.Transport = &http.Transport{ResponseHeaderTimeout: 30 * time.Second}

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = upstream.Host
		switch kind {
		case backendLoki:
			req.URL.Path = normalizeLokiUpstreamPath(req.URL.Path, pathPrefix)
			req.URL.RawPath = ""
		case backendGraphQL:
			// GraphQL is a single endpoint: whatever came in under /graphql
			// goes to exactly the path in GRAPHQL_URL. Client headers
			// (Authorization, Cookie) are forwarded untouched — the token
			// always comes from the caller, never from this service.
			req.URL.Path = upstream.Path
			req.URL.RawPath = ""
		}
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		req := resp.Request
		path := ""
		if req != nil {
			path = req.URL.Path
		}
		slog.Info("upstream response",
			"path", path,
			"status", resp.StatusCode,
			"content_type", resp.Header.Get("Content-Type"),
			"content_encoding", resp.Header.Get("Content-Encoding"),
		)
		switch kind {
		case backendElastic:
			return modifyElasticResponse(resp, cfg, m, path)
		case backendGraphQL:
			return modifyGraphQLResponse(resp, cfg, gql)
		default:
			return modifyResponse(resp, cfg, m)
		}
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("upstream error",
			"err", err,
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
		)
		if kind == backendGraphQL {
			// The /graphql contract is "always JSON", and an unreachable
			// upstream never produces a response for ModifyResponse to
			// rewrite — emit the envelope here instead.
			writeGraphQLGatewayError(w)
			return
		}
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	return rp, nil
}

// normalizeLokiUpstreamPath maps the path left after StripPrefix("/loki") onto the
// upstream Loki (or gateway) path.
//
//   - prefix "" (LOKI_URL has no path): leave the path as-is after StripPrefix.
//     Grafana with datasource .../loki often calls /loki/loki/api/v1/... → after
//     strip that is /loki/api/v1/..., which gateways under /loki need. Do NOT strip
//     that remaining /loki — that broke prod (404 on /api/v1/...).
//   - prefix "/loki" (LOKI_URL=https://host/loki): ensure exactly one /loki before
//     /api/..., so both /loki/api/... and /loki/loki/api/... from Grafana work.
func normalizeLokiUpstreamPath(path, prefix string) string {
	if prefix == "" {
		return path
	}
	if path == prefix || strings.HasPrefix(path, prefix+"/") {
		return path
	}
	if path == "/api" || strings.HasPrefix(path, "/api/") {
		return prefix + path
	}
	return path
}

func modifyResponse(resp *http.Response, cfg config.Config, m *masker.Masker) error {
	return modifyResponseBody(resp, cfg, false, func(body []byte) ([]byte, error) {
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "json") && !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
			return body, nil
		}
		out, _, err := MaskResponseBody(body, m)
		if err != nil {
			return body, err
		}
		return out, nil
	})
}

func modifyElasticResponse(resp *http.Response, cfg config.Config, m *masker.Masker, path string) error {
	if !strings.HasSuffix(path, "_search") && !strings.HasSuffix(path, "_msearch") {
		return nil
	}
	return modifyResponseBody(resp, cfg, false, func(body []byte) ([]byte, error) {
		out, _, err := MaskElasticResponseBody(body, m, cfg.ElasticMessageField)
		if err != nil {
			return body, err
		}
		return out, nil
	})
}

// modifyGraphQLResponse rewrites every GraphQL response into masked JSON.
// Error statuses are processed too (an ingress HTML 502 must still leave as
// a GraphQL error envelope), and Content-Type is forced to application/json.
func modifyGraphQLResponse(resp *http.Response, cfg config.Config, mk GraphQLMaskers) error {
	if isProtocolUpgrade(resp) {
		// GraphQL subscriptions over websocket: proxy the handshake verbatim.
		return nil
	}
	status := resp.StatusCode
	err := modifyResponseBody(resp, cfg, true, func(body []byte) ([]byte, error) {
		out, changed, err := MaskGraphQLResponseBody(body, mk, status)
		if err != nil {
			return body, err
		}
		slog.Info("graphql response masking",
			"status", status,
			"changed", changed,
			"bytes_in", len(body),
			"bytes_out", len(out),
		)
		return out, nil
	})
	if err != nil {
		return err
	}
	resp.Header.Set("Content-Type", "application/json; charset=utf-8")
	return nil
}

// graphQLRuleKeys flattens the graphql block's key names for the startup log,
// so the rules the process actually loaded are visible in the pod logs.
func graphQLRuleKeys(rules []config.JSONKeyRule) []string {
	var keys []string
	for _, r := range rules {
		keys = append(keys, r.Keys...)
	}
	return keys
}

// writeGraphQLGatewayError emits a GraphQL error envelope for a request that
// never reached the upstream. The error text is this service's own, so there
// is nothing from the upstream to mask.
func writeGraphQLGatewayError(w http.ResponseWriter) {
	const body = `{"data":null,"errors":[{"message":"upstream unreachable",` +
		`"extensions":{"upstream_status":502}}]}`
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, body)
}

// isProtocolUpgrade reports whether resp is a protocol upgrade (websocket,
// h2c) that must be proxied verbatim. ReverseProxy runs ModifyResponse on 101
// responses before it strips hop-by-hop headers, so both signals are available
// here.
func isProtocolUpgrade(resp *http.Response) bool {
	return resp.StatusCode == http.StatusSwitchingProtocols ||
		strings.EqualFold(resp.Header.Get("Upgrade"), "websocket")
}

// modifyResponseBody buffers, decompresses (if gzip), size-limits, and hands
// the response body to mask for optional rewriting, then writes the result
// back onto resp. If mask returns an error, the original body is used
// instead (passthrough). maskErrors=false leaves 4xx/5xx bodies untouched.
func modifyResponseBody(resp *http.Response, cfg config.Config, maskErrors bool, mask func([]byte) ([]byte, error)) error {
	if resp.StatusCode >= 400 && !maskErrors {
		return nil
	}
	if resp.Body == nil {
		return nil
	}
	if isProtocolUpgrade(resp) {
		return nil
	}

	var reader io.Reader = resp.Body
	gzipped := strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip")
	if gzipped {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			slog.Warn("gzip reader failed, passthrough", "err", err)
			return nil
		}
		defer func() { _ = gz.Close() }()
		reader = gz
	}

	limited := io.LimitReader(reader, cfg.MaxResponseBytes+1)
	body, err := io.ReadAll(limited)
	_ = resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return err
	}

	setBody := func(b []byte) {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.Header.Del("Content-Encoding")
		// Upstream often sends Transfer-Encoding: chunked; after we buffer the
		// body we must clear it or clients can see an empty/corrupt payload
		// (Grafana then reports "unknown result type: ").
		resp.Header.Del("Transfer-Encoding")
		resp.Trailer = nil
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}

	if int64(len(body)) > cfg.MaxResponseBytes {
		// Body is already truncated by LimitReader — sending it breaks JSON
		// clients. Fail closed so ReverseProxy returns 502 instead of a
		// partial payload that Grafana surfaces as "unknown result type: ".
		slog.Warn("response too large for masking buffer", "size", len(body), "limit", cfg.MaxResponseBytes)
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return fmt.Errorf("response exceeds MAX_RESPONSE_BYTES (%d)", cfg.MaxResponseBytes)
	}

	out, err := mask(body)
	if err != nil {
		slog.Warn("mask rewrite failed, passthrough", "err", err)
		out = body
	}
	setBody(out)
	return nil
}
