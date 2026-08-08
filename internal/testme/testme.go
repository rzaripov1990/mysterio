package testme

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"

	config "mysterio/configs"
	"mysterio/internal/masker"
)

//go:embed page.html
var pageTemplate string

//go:embed vendor
var vendorFS embed.FS

const maxRequestBytes = 1 << 20 // 1 MiB

// NewHandler returns an http.Handler serving the masking-test UI and its
// API under basePath (e.g. "" for root, or "/mysterio"):
//   - GET  {basePath}/test-me           the HTML page
//   - GET  {basePath}/test-me/api/rules the embedded rules.yaml, verbatim
//   - POST {basePath}/test-me/api/mask  masks a log line against rules
//     supplied in the request body (not the service's live rules)
//   - GET  {basePath}/test-me/vendor/*  vendored CodeMirror assets (no CDN)
func NewHandler(basePath string, rulesYAML []byte) http.Handler {
	tmpl := template.Must(template.New("page").Parse(pageTemplate))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, struct{ BasePath string }{BasePath: basePath}); err != nil {
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

	mux.HandleFunc("POST "+basePath+"/test-me/api/mask", handleMask)

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

func handleMask(w http.ResponseWriter, r *http.Request) {
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

	m := masker.New(rules)
	result := m.Apply(req.Log)

	_ = json.NewEncoder(w).Encode(maskResponse{Result: result})
}

func writeMaskError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(maskResponse{Error: msg})
}
