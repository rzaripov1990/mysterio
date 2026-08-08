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
)

func NewHandler(cfg config.Config, m *masker.Masker) (http.Handler, error) {
	if !cfg.LokiEnabled && !cfg.ElasticEnabled {
		return nil, fmt.Errorf("no backend enabled: set LOKI_ENABLED and/or ELASTIC_ENABLED")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	if cfg.LokiEnabled {
		rp, err := newReverseProxy(cfg.LokiURL, cfg, m, false)
		if err != nil {
			return nil, fmt.Errorf("loki upstream: %w", err)
		}
		mux.Handle("/loki/", http.StripPrefix("/loki", rp))
	}

	if cfg.ElasticEnabled {
		rp, err := newReverseProxy(cfg.ElasticURL, cfg, m, true)
		if err != nil {
			return nil, fmt.Errorf("elastic upstream: %w", err)
		}
		mux.Handle("/elastic/", http.StripPrefix("/elastic", rp))
	}

	if cfg.TestMeEnabled {
		tm := testme.NewHandler(cfg.BasePath, cfg.RawRulesYAML)
		mux.Handle(cfg.BasePath+"/test-me", tm)
		mux.Handle(cfg.BasePath+"/test-me/", tm)
	}

	return withLogging(mux), nil
}

func newReverseProxy(rawUpstream string, cfg config.Config, m *masker.Masker, elastic bool) (*httputil.ReverseProxy, error) {
	upstream, err := url.Parse(rawUpstream)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.Transport = &http.Transport{ResponseHeaderTimeout: 30 * time.Second}

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = upstream.Host
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
		if elastic {
			return modifyElasticResponse(resp, cfg, m, path)
		}
		return modifyResponse(resp, cfg, m)
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("upstream error",
			"err", err,
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
		)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	return rp, nil
}

func modifyResponse(resp *http.Response, cfg config.Config, m *masker.Masker) error {
	return modifyResponseBody(resp, cfg, func(body []byte) ([]byte, error) {
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
	return modifyResponseBody(resp, cfg, func(body []byte) ([]byte, error) {
		out, _, err := MaskElasticResponseBody(body, m)
		if err != nil {
			return body, err
		}
		return out, nil
	})
}

// modifyResponseBody buffers, decompresses (if gzip), size-limits, and hands
// the response body to mask for optional rewriting, then writes the result
// back onto resp. If mask returns an error, the original body is used
// instead (passthrough).
func modifyResponseBody(resp *http.Response, cfg config.Config, mask func([]byte) ([]byte, error)) error {
	if resp.StatusCode >= 400 {
		return nil
	}
	if resp.Body == nil {
		return nil
	}
	if strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
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
		resp.ContentLength = int64(len(b))
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}

	if int64(len(body)) > cfg.MaxResponseBytes {
		slog.Warn("response too large, skip masking", "size", len(body))
		setBody(body)
		return nil
	}

	out, err := mask(body)
	if err != nil {
		slog.Warn("mask rewrite failed, passthrough", "err", err)
		out = body
	}
	setBody(out)
	return nil
}
