package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	config "mystrio/configs"
	"mystrio/internal/masker"
	"mystrio/internal/proxy"
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
	return masker.New(rules)
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
		_, _ = w.Write([]byte(`{"status":"success"}`))
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
