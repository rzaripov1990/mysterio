package testme_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mysterio/internal/testme"
	"mysterio/internal/token"
)

const testRulesYAML = `
json_keys:
  - name: iin
    keys: [iin]
    replace: "************"
`

func TestNewHandler_ServesPage(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-me", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("expected text/html content type, got %q", ct)
	}
}

func TestNewHandler_RulesEndpoint_ReturnsEmbeddedBytes(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-me/api/rules", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != testRulesYAML {
		t.Fatalf("unexpected rules body: %q", rec.Body.String())
	}
}

func TestNewHandler_Mask_ValidRules(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)
	body, _ := json.Marshal(map[string]string{
		"rules": testRulesYAML,
		"log":   `{"iin":"999888777666"}`,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/mask", bytes.NewReader(body))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp.Result, "************") {
		t.Fatalf("expected masked iin in result: %s", resp.Result)
	}
}

func TestNewHandler_Mask_InvalidRulesYAML(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)
	body, _ := json.Marshal(map[string]string{
		"rules": "regex:\n  - name: bad\n    pattern: \"(\"\n    replace: x",
		"log":   "hello",
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/mask", bytes.NewReader(body))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestNewHandler_Mask_InvalidRequestJSON(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/mask", strings.NewReader("not json"))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNewHandler_Mask_EmptyLog(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)
	body, _ := json.Marshal(map[string]string{"rules": testRulesYAML, "log": ""})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/mask", bytes.NewReader(body))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty log, got %d", rec.Code)
	}
}

func TestNewHandler_BasePath_PrefixesRoutes(t *testing.T) {
	h := testme.NewHandler("/mysterio", []byte(testRulesYAML), nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-me", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected root /test-me to 404 when basePath is set, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/mysterio/test-me", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected /mysterio/test-me to serve the page, got %d", rec.Code)
	}
}

func TestNewHandler_VendorAssets_Served(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)

	for _, name := range []string{"codemirror.min.js", "codemirror.min.css", "yaml.min.js"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test-me/vendor/"+name, nil)
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for /test-me/vendor/%s, got %d", name, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("expected non-empty body for %s", name)
		}
	}
}

func TestNewHandler_Page_UsesBasePathForVendorAssets(t *testing.T) {
	h := testme.NewHandler("/mysterio", []byte(testRulesYAML), nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mysterio/test-me", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/mysterio/test-me/vendor/codemirror.min.js") {
		t.Fatalf("expected page to reference base-path-prefixed vendor script, got: %s", body)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/mysterio/test-me/vendor/codemirror.min.js", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected vendor asset to be served under basePath, got %d", rec.Code)
	}
}

func TestHMAC_Lookup(t *testing.T) {
	tok := token.New([]byte("0123456789abcdef0123456789abcdef"))
	h := testme.NewHandler("", []byte(testRulesYAML), tok)
	body, _ := json.Marshal(map[string]string{"value": "890501402951", "normalize": "digits"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/hmac", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `~nAqddoqkCK8`) {
		t.Fatal(rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "0123456789abcdef") {
		t.Fatal("key leaked")
	}
}

func TestHMAC_NoTokenizer_503(t *testing.T) {
	h := testme.NewHandler("", []byte(testRulesYAML), nil)
	body, _ := json.Marshal(map[string]string{"value": "890501402951", "normalize": "digits"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/hmac", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestMask_HMACUsesServerTokenizer(t *testing.T) {
	tok := token.New([]byte("0123456789abcdef0123456789abcdef"))
	hmacRules := `
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
    normalize: digits
`
	h := testme.NewHandler("", []byte(hmacRules), tok)
	body, _ := json.Marshal(map[string]string{"rules": hmacRules, "log": `{"iin":"890501402951"}`})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/mask", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `~nAqddoqkCK8`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestMask_HMACNoTokenizer_400(t *testing.T) {
	hmacRules := `
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
`
	h := testme.NewHandler("", []byte(hmacRules), nil)
	body, _ := json.Marshal(map[string]string{"rules": hmacRules, "log": `{"iin":"890501402951"}`})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/mask", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestHMAC_EmptyValue_400(t *testing.T) {
	tok := token.New([]byte("0123456789abcdef0123456789abcdef"))
	h := testme.NewHandler("", []byte(testRulesYAML), tok)
	body, _ := json.Marshal(map[string]string{"value": "", "normalize": "digits"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/hmac", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestHMAC_Asterisks_ReturnsStars(t *testing.T) {
	tok := token.New([]byte("0123456789abcdef0123456789abcdef"))
	h := testme.NewHandler("", []byte(testRulesYAML), tok)
	body, _ := json.Marshal(map[string]string{"value": "***", "normalize": "none"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test-me/api/hmac", bytes.NewReader(body))
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"token":"***"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestPage_DoesNotEmbedKey(t *testing.T) {
	tok := token.New([]byte("0123456789abcdef0123456789abcdef"))
	h := testme.NewHandler("", []byte(testRulesYAML), tok)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-me", nil)
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "0123456789abcdef") {
		t.Fatal("key leaked into HTML")
	}
}
