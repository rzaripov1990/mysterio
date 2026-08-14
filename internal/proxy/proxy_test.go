package proxy_test

import (
	"encoding/json"
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
