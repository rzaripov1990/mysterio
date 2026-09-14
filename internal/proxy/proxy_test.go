package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/proxy"
)

func testMasker(t *testing.T) *masker.Masker {
	t.Helper()
	rules, err := config.LoadRules([]byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "************"
`))
	if err != nil {
		t.Fatal(err)
	}
	return mustMasker(t, rules)
}

func mustMasker(t *testing.T, rules config.Rules) *masker.Masker {
	t.Helper()
	m, err := masker.New(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNewHandler_NoBackendEnabled_Error(t *testing.T) {
	cfg := config.Config{MaxResponseBytes: 1 << 20}
	if _, err := proxy.NewHandler(cfg, testMasker(t)); err == nil {
		t.Fatal("expected error when no backend is enabled")
	}
}

func TestNewHandler_LokiRouting_StripsPrefix(t *testing.T) {
	var gotPath string
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer loki.Close()

	cfg := config.Config{MaxResponseBytes: 1 << 20, LokiEnabled: true, LokiURL: loki.URL}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range", nil)
	h.ServeHTTP(rec, req)

	if gotPath != "/api/v1/query_range" {
		t.Fatalf("expected upstream path /api/v1/query_range, got %q", gotPath)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestNewHandler_LokiRouting_GatewayPrefix(t *testing.T) {
	// LOKI_URL includes /loki (common ingress). Grafana may call /loki/api/... or
	// /loki/loki/api/...; both must land on upstream /loki/api/v1/query_range.
	var gotPath string
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer loki.Close()

	cfg := config.Config{
		MaxResponseBytes: 1 << 20,
		LokiEnabled:      true,
		LokiURL:          loki.URL + "/loki",
	}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, in := range []string{"/loki/api/v1/query_range", "/loki/loki/api/v1/query_range"} {
		gotPath = ""
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, in, nil)
		h.ServeHTTP(rec, req)
		if gotPath != "/loki/api/v1/query_range" {
			t.Fatalf("%s: expected upstream /loki/api/v1/query_range, got %q", in, gotPath)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d body=%s", in, rec.Code, rec.Body.String())
		}
		var root map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
			t.Fatalf("%s: response not JSON: %v body=%q", in, err, rec.Body.String())
		}
		rt, _ := root["data"].(map[string]any)["resultType"].(string)
		if rt != "streams" {
			t.Fatalf("%s: resultType=%q want streams", in, rt)
		}
	}
}

func TestNewHandler_LokiQueryRange_MaskedPreservesResultType(t *testing.T) {
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Chunked-style response from Loki (no Content-Length).
		_, _ = w.Write([]byte(`{
		  "status":"success",
		  "data":{
		    "resultType":"streams",
		    "result":[{
		      "stream":{"k8s_app":"a2a/x"},
		      "values":[["1","{\"iin\":\"123456789012\",\"ip\":\"10.120.34.195\"}"]]
		    }]
		  }
		}`))
	}))
	defer loki.Close()

	cfg := config.Config{
		MaxResponseBytes: 1 << 20,
		LokiEnabled:      true,
		LokiURL:          loki.URL + "/loki",
	}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/loki/loki/api/v1/query_range", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if te := rec.Header().Get("Transfer-Encoding"); te != "" {
		t.Fatalf("Transfer-Encoding should be cleared after buffering, got %q", te)
	}
	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatalf("client must receive valid JSON: %v body=%q", err, rec.Body.String())
	}
	data, _ := root["data"].(map[string]any)
	if data["resultType"] != "streams" {
		t.Fatalf("resultType=%v want streams (Grafana shows unknown result type if missing)", data["resultType"])
	}
}

func TestNewHandler_LokiRouting_NoURLPath_KeepsDoublePrefix(t *testing.T) {
	// LOKI_URL without /loki path + Grafana double-prefix (datasource ends with /loki):
	// /loki/loki/api → strip → /loki/api — must stay /loki/api for gateways (do not
	// strip again to /api, that returns 404 page not found).
	var gotPath string
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer loki.Close()

	cfg := config.Config{MaxResponseBytes: 1 << 20, LokiEnabled: true, LokiURL: loki.URL}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/loki/loki/api/v1/query_range", nil)
	h.ServeHTTP(rec, req)
	if gotPath != "/loki/api/v1/query_range" {
		t.Fatalf("expected upstream /loki/api/v1/query_range, got %q", gotPath)
	}
}

func TestNewHandler_ElasticSearch_Masked(t *testing.T) {
	elastic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_source":{"iin":"999888777666"}}]}}`))
	}))
	defer elastic.Close()

	cfg := config.Config{MaxResponseBytes: 1 << 20, ElasticEnabled: true, ElasticURL: elastic.URL}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/elastic/logs-1/_search", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatal(err)
	}
	src := root["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)
	if src["iin"] != "************" {
		t.Fatalf("iin not masked in response: %s", rec.Body.String())
	}
}

func TestNewHandler_ElasticMapping_NotMasked(t *testing.T) {
	elastic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hits":{"hits":[{"_source":{"iin":"999888777666"}}]}}`))
	}))
	defer elastic.Close()

	cfg := config.Config{MaxResponseBytes: 1 << 20, ElasticEnabled: true, ElasticURL: elastic.URL}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/elastic/logs-1/_mapping", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatal(err)
	}
	src := root["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)
	if src["iin"] != "999888777666" {
		t.Fatalf("iin should NOT be masked on non-_search endpoint, got: %s", rec.Body.String())
	}
}

func TestNewHandler_Healthz(t *testing.T) {
	cfg := config.Config{MaxResponseBytes: 1 << 20, LokiEnabled: true, LokiURL: "http://127.0.0.1:1"}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("unexpected healthz response: %d %q", rec.Code, rec.Body.String())
	}
}

func TestNewHandler_TestMeDisabled_404(t *testing.T) {
	cfg := config.Config{MaxResponseBytes: 1 << 20, LokiEnabled: true, LokiURL: "http://127.0.0.1:1"}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-me", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when TestMeEnabled=false, got %d", rec.Code)
	}
}

func TestNewHandler_TestMeEnabled_ServesPage(t *testing.T) {
	cfg := config.Config{
		MaxResponseBytes: 1 << 20,
		LokiEnabled:      true,
		LokiURL:          "http://127.0.0.1:1",
		TestMeEnabled:    true,
	}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-me", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when TestMeEnabled=true, got %d", rec.Code)
	}
}

func TestNewHandler_TestMeEnabled_BasePath_IngressRewrite(t *testing.T) {
	cfg := config.Config{
		MaxResponseBytes: 1 << 20,
		LokiEnabled:      true,
		LokiURL:          "http://127.0.0.1:1",
		TestMeEnabled:    true,
		BasePath:         "/mysterio",
	}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-me", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /test-me (path after ingress rewrite), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "/mysterio/test-me/vendor/") {
		t.Fatalf("expected HTML to use public BASE_PATH, got: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/mysterio/test-me", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on prefixed path (ingress already stripped it), got %d", rec.Code)
	}
}

const graphqlRulesYAML = `
json_keys:
  - name: global_only
    keys: [globalSecret]
    replace: "GLOBAL-MASKED"
graphql:
  json_keys:
    - name: iin
      keys: [iin]
      replace: "************"
`

func graphqlCfg(t *testing.T, upstreamURL string) config.Config {
	t.Helper()
	rules, err := config.LoadRules([]byte(graphqlRulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	return config.Config{
		MaxResponseBytes: 1 << 20,
		GraphQLEnabled:   true,
		GraphQLURL:       upstreamURL,
		Rules:            rules,
	}
}

func TestNewHandler_GraphQLRouting_UsesUpstreamPathAndForwardsToken(t *testing.T) {
	var gotPath, gotAuth, gotMethod string
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer upstream.Close()

	cfg := graphqlCfg(t, upstream.URL+"/api/graphql")
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{ok}"}`))
	req.Header.Set("Authorization", "Bearer outside-token")
	h.ServeHTTP(rec, req)

	if gotPath != "/api/graphql" {
		t.Fatalf("expected upstream path /api/graphql, got %q", gotPath)
	}
	if gotAuth != "Bearer outside-token" {
		t.Fatalf("expected client Authorization forwarded as-is, got %q", gotAuth)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %q", gotMethod)
	}
	if string(gotBody) != `{"query":"{ok}"}` {
		t.Fatalf("request body altered: %q", gotBody)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestNewHandler_GraphQLResponse_MaskedWithGraphQLBlockOnly(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"client":{"iin":"900101300123","globalSecret":"keep-me"}}}`))
	}))
	defer upstream.Close()

	h, err := proxy.NewHandler(graphqlCfg(t, upstream.URL+"/graphql"), testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{c}"}`)))

	body := rec.Body.String()
	if strings.Contains(body, "900101300123") {
		t.Fatalf("graphql json_keys not applied: %s", body)
	}
	if !strings.Contains(body, `"globalSecret":"keep-me"`) {
		t.Fatalf("global json_keys must not apply on /graphql: %s", body)
	}
}

func TestNewHandler_GraphQLResponse_PartialMaskKeepsOrder(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json;charset=utf-8")
		_, _ = w.Write([]byte(`{"data":{"Person":[{"FIRSTNAME":{"RU":"РАВИЛЬ","EN":null},"IIN":"900621300906","BALANCE":1500.25}]}}`))
	}))
	defer upstream.Close()

	rules, err := config.LoadRules([]byte(`
graphql:
  json_keys:
    - name: names
      keys: [FIRSTNAME.*]
      keep_first: 1
      replace: "***"
    - name: iin
      keys: [Person.IIN]
      keep_first: 4
      keep_last: 2
      replace: "******"
    - name: balance
      keys: [BALANCE]
      replace_number: 0
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := graphqlCfg(t, upstream.URL+"/graphql")
	cfg.Rules = rules
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{p}"}`)))

	want := `{"data":{"Person":[{"FIRSTNAME":{"RU":"Р***","EN":null},"IIN":"9006******06","BALANCE":0}]}}`
	if got := rec.Body.String(); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestNewHandler_GraphQLResponse_AlwaysJSONContentType(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<html>502 Bad Gateway iin=900101300123</html>`))
	}))
	defer upstream.Close()

	h, err := proxy.NewHandler(graphqlCfg(t, upstream.URL+"/graphql"), testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{c}"}`)))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json, got %q", ct)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected upstream status 502 preserved, got %d", rec.Code)
	}
	if !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("expected JSON body, got %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "upstream_status") {
		t.Fatalf("expected error envelope, got %s", rec.Body.String())
	}
}

func TestNewHandler_GraphQLDisabled_404(t *testing.T) {
	cfg := config.Config{MaxResponseBytes: 1 << 20, LokiEnabled: true, LokiURL: "http://loki:3100"}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when GRAPHQL_ENABLED is false, got %d", rec.Code)
	}
}

func TestNewHandler_GraphQLEnabledOnly_IsValidBackend(t *testing.T) {
	cfg := config.Config{MaxResponseBytes: 1 << 20, GraphQLEnabled: true, GraphQLURL: "http://api:4000/graphql"}
	if _, err := proxy.NewHandler(cfg, testMasker(t)); err != nil {
		t.Fatalf("graphql-only handler should build: %v", err)
	}
}

func TestNewHandler_GraphQLUpstreamUnreachable_JSONEnvelope(t *testing.T) {
	// Port 1 on loopback refuses connections, so the request never reaches a
	// response and ReverseProxy falls back to ErrorHandler.
	h, err := proxy.NewHandler(graphqlCfg(t, "http://127.0.0.1:1/graphql"), testMasker(t))
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"{c}"}`)))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json, got %q", ct)
	}
	if !json.Valid(rec.Body.Bytes()) {
		t.Fatalf("expected a JSON body even when the upstream is unreachable, got %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"errors"`) {
		t.Fatalf("expected a GraphQL error envelope, got %s", rec.Body.String())
	}
}

func TestNewHandler_LokiUpstreamUnreachable_StaysPlainText(t *testing.T) {
	cfg := config.Config{MaxResponseBytes: 1 << 20, LokiEnabled: true, LokiURL: "http://127.0.0.1:1"}
	h, err := proxy.NewHandler(cfg, testMasker(t))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rec.Code)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "bad gateway" {
		t.Fatalf("loki error response changed: %q", body)
	}
}
