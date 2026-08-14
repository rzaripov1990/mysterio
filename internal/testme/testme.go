package testme

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"regexp"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/token"
)

//go:embed page.html
var pageTemplate string

//go:embed vendor
var vendorFS embed.FS

const maxRequestBytes = 1 << 20 // 1 MiB

var allStars = regexp.MustCompile(`^\*+$`)

// NewHandler returns an http.Handler serving the masking-test UI and its
// API under basePath (e.g. "" for root, or "/mysterio"):
//   - GET  {basePath}/test-me           the HTML page
//   - GET  {basePath}/test-me/api/rules the embedded rules.yaml, verbatim
//   - POST {basePath}/test-me/api/mask  masks a log line against rules
//     supplied in the request body (not the service's live rules)
//   - POST {basePath}/test-me/api/hmac  hashes a value with the process key
//   - GET  {basePath}/test-me/vendor/*  vendored CodeMirror assets (no CDN)
func NewHandler(basePath string, rulesYAML []byte, tok *token.Tokenizer) http.Handler {
	tmpl := template.Must(template.New("page").Parse(pageTemplate))
	var buf bytes.Buffer
	data := struct {
		BasePath    string
		HMACEnabled bool
	}{BasePath: basePath, HMACEnabled: tok != nil}
	if err := tmpl.Execute(&buf, data); err != nil {
		panic("testme: render page template: " + err.Error())
	}
	pageHTML := buf.Bytes()

	vendorSub, err := fs.Sub(vendorFS, "vendor")
	if err != nil {
		panic("testme: vendor assets: " + err.Error())
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET "+basePath+"/test-me", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(pageHTML)
	})

	mux.HandleFunc("GET "+basePath+"/test-me/api/rules", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(rulesYAML)
	})

	mux.HandleFunc("POST "+basePath+"/test-me/api/mask", func(w http.ResponseWriter, r *http.Request) {
		handleMask(w, r, tok)
	})
	mux.HandleFunc("POST "+basePath+"/test-me/api/hmac", func(w http.ResponseWriter, r *http.Request) {
		handleHMAC(w, r, tok)
	})

	mux.Handle("GET "+basePath+"/test-me/vendor/",
		http.StripPrefix(basePath+"/test-me/vendor/", http.FileServerFS(vendorSub)))

	return mux
}

type maskRequest struct {
	Rules string `json:"rules"`
	Log   string `json:"log"`
}

type maskResponse struct {
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type hmacRequest struct {
	Value     string `json:"value"`
	Normalize string `json:"normalize"`
}

type hmacResponse struct {
	Token string `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

func handleMask(w http.ResponseWriter, r *http.Request, tok *token.Tokenizer) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	var req maskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMaskError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Log == "" {
		writeMaskError(w, http.StatusBadRequest, "log is empty")
		return
	}

	rules, err := config.LoadRules([]byte(req.Rules))
	if err != nil {
		writeMaskError(w, http.StatusBadRequest, err.Error())
		return
	}

	m, err := masker.New(rules, tok)
	if err != nil {
		writeMaskError(w, http.StatusBadRequest, err.Error())
		return
	}
	result := m.Apply(req.Log)

	_ = json.NewEncoder(w).Encode(maskResponse{Result: result})
}

func handleHMAC(w http.ResponseWriter, r *http.Request, tok *token.Tokenizer) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if tok == nil {
		writeHMACError(w, http.StatusServiceUnavailable, "MASK_HMAC_KEY is not set")
		return
	}

	var req hmacRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHMACError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Value == "" {
		writeHMACError(w, http.StatusBadRequest, "value is empty")
		return
	}
	switch req.Normalize {
	case "", "none", "digits", "lower":
	default:
		writeHMACError(w, http.StatusBadRequest, "unknown normalize")
		return
	}

	if token.IsToken(req.Value) {
		_ = json.NewEncoder(w).Encode(hmacResponse{Token: req.Value})
		return
	}
	if allStars.MatchString(req.Value) {
		_ = json.NewEncoder(w).Encode(hmacResponse{Token: "***"})
		return
	}
	out := tok.Token(req.Value, req.Normalize)
	if out == "" {
		out = "***"
	}
	_ = json.NewEncoder(w).Encode(hmacResponse{Token: out})
}

func writeMaskError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(maskResponse{Error: msg})
}

func writeHMACError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(hmacResponse{Error: msg})
}
