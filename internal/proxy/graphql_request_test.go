package proxy_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"mysterio/internal/proxy"
)

type graphqlUpstream struct {
	srv  *httptest.Server
	hits atomic.Int32
	body atomic.Value // last request body
}

func newGraphQLUpstream(t *testing.T) *graphqlUpstream {
	t.Helper()
	u := &graphqlUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		u.body.Store(string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func graphqlHandler(t *testing.T, u *graphqlUpstream) http.Handler {
	t.Helper()
	h, err := proxy.NewHandler(graphqlCfg(t, u.srv.URL+"/graphql"), testMasker(t))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func postGraphQL(h http.Handler, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func jsonBody(t *testing.T, query string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"query": query, "variables": map[string]any{"IIN": "900621300906"}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertRejected checks the response is a GraphQL error with the given code
// and that the request never reached the upstream.
func assertRejected(t *testing.T, rec *httptest.ResponseRecorder, u *graphqlUpstream, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status=%d want %d body=%s", rec.Code, status, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type=%q want application/json", ct)
	}
	var env struct {
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				Code string `json:"code"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil || len(env.Errors) != 1 {
		t.Fatalf("expected one GraphQL error, got %s (%v)", rec.Body.String(), err)
	}
	if env.Errors[0].Extensions.Code != code {
		t.Fatalf("code=%q want %q body=%s", env.Errors[0].Extensions.Code, code, rec.Body.String())
	}
	if n := u.hits.Load(); n != 0 {
		t.Fatalf("rejected request reached upstream %d time(s)", n)
	}
}

func TestGraphQLRequest_PlainQueryForwardedUnchanged(t *testing.T) {
	u := newGraphQLUpstream(t)
	h := graphqlHandler(t, u)
	body := jsonBody(t, `query q($IIN: String! = "0") {
  # comment with a: colon
  Person(IIN: $IIN, filter: {kind: "a:b"}) @include(if: true) {
    IIN
    FIRSTNAME { RU }
    ...F
    ... on Person { LASTNAME { RU } }
    note(text: """block: string""")
  }
}
fragment F on Person { MIDDLENAME { RU } }`)
	rec := postGraphQL(h, "application/json; charset=utf-8", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if u.hits.Load() != 1 {
		t.Fatal("expected the request to reach upstream")
	}
	if got := u.body.Load().(string); got != body {
		t.Fatalf("upstream body altered:\n%s\nwant\n%s", got, body)
	}
}

func TestGraphQLRequest_AliasEqualToFieldNameAllowed(t *testing.T) {
	u := newGraphQLUpstream(t)
	rec := postGraphQL(graphqlHandler(t, u), "application/json", jsonBody(t, `{ Person { IIN: IIN } }`))
	if rec.Code != http.StatusOK || u.hits.Load() != 1 {
		t.Fatalf("status=%d hits=%d body=%s", rec.Code, u.hits.Load(), rec.Body.String())
	}
}

func TestGraphQLRequest_AliasesRejected(t *testing.T) {
	cases := map[string]string{
		"field":           `query q($IIN: String!) { Person(IIN: $IIN) { hackIIN: IIN } }`,
		"top-level field": `{ p: Person { IIN } }`,
		"named fragment":  `{ Person { ...F } } fragment F on Person { hackIIN: IIN }`,
		"unused fragment": `{ Person { IIN } } fragment F on Person { hackIIN: IIN }`,
		"inline fragment": `{ Person { ... on Person { hackIIN: IIN } } }`,
		"nested":          `{ Person { FIRSTNAME { ru: RU } } }`,
		"second op":       `query a { Person { IIN } } query b { Person { x: IIN } }`,
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			u := newGraphQLUpstream(t)
			rec := postGraphQL(graphqlHandler(t, u), "application/json", jsonBody(t, q))
			assertRejected(t, rec, u, http.StatusBadRequest, "ALIASES_NOT_ALLOWED")
		})
	}
}

func TestGraphQLRequest_BatchCheckedPerOperation(t *testing.T) {
	u := newGraphQLUpstream(t)
	body := `[` + jsonBody(t, `{ Person { IIN } }`) + `,` + jsonBody(t, `{ Person { x: IIN } }`) + `]`
	assertRejected(t, postGraphQL(graphqlHandler(t, u), "application/json", body), u, http.StatusBadRequest, "ALIASES_NOT_ALLOWED")

	ok := newGraphQLUpstream(t)
	body = `[` + jsonBody(t, `{ Person { IIN } }`) + `,` + jsonBody(t, `{ Person { FIRSTNAME { RU } } }`) + `]`
	if rec := postGraphQL(graphqlHandler(t, ok), "application/json", body); rec.Code != http.StatusOK || ok.hits.Load() != 1 {
		t.Fatalf("clean batch: status=%d hits=%d body=%s", rec.Code, ok.hits.Load(), rec.Body.String())
	}
}

func TestGraphQLRequest_GETQueryParamChecked(t *testing.T) {
	u := newGraphQLUpstream(t)
	h := graphqlHandler(t, u)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graphql?query="+url.QueryEscape(`{ Person { x: IIN } }`), nil))
	assertRejected(t, rec, u, http.StatusBadRequest, "ALIASES_NOT_ALLOWED")

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/graphql?query="+url.QueryEscape(`{ Person { IIN } }`), nil))
	if rec.Code != http.StatusOK || u.hits.Load() != 1 {
		t.Fatalf("clean GET: status=%d hits=%d body=%s", rec.Code, u.hits.Load(), rec.Body.String())
	}
}

// A server may read ?query= even on POST; every copy of the query is checked.
func TestGraphQLRequest_POSTWithQueryParamChecked(t *testing.T) {
	u := newGraphQLUpstream(t)
	req := httptest.NewRequest(http.MethodPost, "/graphql?query="+url.QueryEscape(`{ Person { x: IIN } }`), strings.NewReader(jsonBody(t, `{ Person { IIN } }`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	graphqlHandler(t, u).ServeHTTP(rec, req)
	assertRejected(t, rec, u, http.StatusBadRequest, "ALIASES_NOT_ALLOWED")
}

// Duplicate keys are resolved differently by different JSON parsers (first
// wins, last wins, error), so the query we check might not be the one the
// upstream runs.
func TestGraphQLRequest_DuplicateQueryKeyRejected(t *testing.T) {
	u := newGraphQLUpstream(t)
	body := `{"query":"{ Person { x: IIN } }","query":"{ Person { IIN } }"}`
	assertRejected(t, postGraphQL(graphqlHandler(t, u), "application/json", body), u, http.StatusBadRequest, "INVALID_REQUEST")
}

func TestGraphQLRequest_UncheckableRequestsRejected(t *testing.T) {
	cases := []struct {
		name, method, contentType, body string
		status                          int
		code                            string
	}{
		{"parse error", http.MethodPost, "application/json", `{"query":"{ Person { IIN "}`, http.StatusBadRequest, "GRAPHQL_PARSE_FAILED"},
		{"persisted query hash only", http.MethodPost, "application/json", `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`, http.StatusBadRequest, "QUERY_REQUIRED"},
		{"null query", http.MethodPost, "application/json", `{"query":null}`, http.StatusBadRequest, "QUERY_REQUIRED"},
		{"non-string query", http.MethodPost, "application/json", `{"query":42}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"invalid json", http.MethodPost, "application/json", `{"query":`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"trailing data", http.MethodPost, "application/json", `{"query":"{ a }"} {"query":"{ x: a }"}`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"empty batch", http.MethodPost, "application/json", `[]`, http.StatusBadRequest, "INVALID_REQUEST"},
		{"application/graphql", http.MethodPost, "application/graphql", `{ Person { x: IIN } }`, http.StatusBadRequest, "UNSUPPORTED_REQUEST"},
		{"multipart", http.MethodPost, "multipart/form-data; boundary=x", "--x--", http.StatusBadRequest, "UNSUPPORTED_REQUEST"},
		{"GET without query", http.MethodGet, "", "", http.StatusBadRequest, "QUERY_REQUIRED"},
		{"PUT", http.MethodPut, "application/json", `{"query":"{ a }"}`, http.StatusMethodNotAllowed, "UNSUPPORTED_REQUEST"},
		{"too large", http.MethodPost, "application/json", `{"query":"{ a }","pad":"` + strings.Repeat("x", 1<<20) + `"}`, http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := newGraphQLUpstream(t)
			req := httptest.NewRequest(c.method, "/graphql", strings.NewReader(c.body))
			if c.contentType != "" {
				req.Header.Set("Content-Type", c.contentType)
			}
			rec := httptest.NewRecorder()
			graphqlHandler(t, u).ServeHTTP(rec, req)
			assertRejected(t, rec, u, c.status, c.code)
		})
	}
}

func TestGraphQLRequest_WebsocketUpgradeRejected(t *testing.T) {
	u := newGraphQLUpstream(t)
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Protocol", "graphql-transport-ws")
	rec := httptest.NewRecorder()
	graphqlHandler(t, u).ServeHTTP(rec, req)
	assertRejected(t, rec, u, http.StatusBadRequest, "WEBSOCKET_NOT_ALLOWED")
}

// CORS preflight carries no query and executes nothing upstream.
func TestGraphQLRequest_OptionsPreflightForwarded(t *testing.T) {
	u := newGraphQLUpstream(t)
	req := httptest.NewRequest(http.MethodOptions, "/graphql", nil)
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	graphqlHandler(t, u).ServeHTTP(rec, req)
	if u.hits.Load() != 1 {
		t.Fatalf("preflight not forwarded: status=%d", rec.Code)
	}
}

func TestGraphQLRequest_SubpathAlsoGuarded(t *testing.T) {
	u := newGraphQLUpstream(t)
	req := httptest.NewRequest(http.MethodPost, "/graphql/v1", strings.NewReader(jsonBody(t, `{ Person { x: IIN } }`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	graphqlHandler(t, u).ServeHTTP(rec, req)
	assertRejected(t, rec, u, http.StatusBadRequest, "ALIASES_NOT_ALLOWED")
}

// Case-insensitive JSON binding (.NET, Go structs) would run the second copy.
func TestGraphQLRequest_QueryKeyCaseVariantsRejected(t *testing.T) {
	u := newGraphQLUpstream(t)
	body := `{"query":"{ Person { IIN } }","QUERY":"{ Person { x: IIN } }"}`
	assertRejected(t, postGraphQL(graphqlHandler(t, u), "application/json", body), u, http.StatusBadRequest, "INVALID_REQUEST")

	u = newGraphQLUpstream(t)
	body = `{"Query":"{ Person { x: IIN } }"}`
	assertRejected(t, postGraphQL(graphqlHandler(t, u), "application/json", body), u, http.StatusBadRequest, "ALIASES_NOT_ALLOWED")
}

func TestGraphQLRequest_URLQueryParamCaseVariantsChecked(t *testing.T) {
	u := newGraphQLUpstream(t)
	rec := httptest.NewRecorder()
	graphqlHandler(t, u).ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/graphql?query="+url.QueryEscape(`{ Person { IIN } }`)+"&Query="+url.QueryEscape(`{ Person { x: IIN } }`), nil))
	assertRejected(t, rec, u, http.StatusBadRequest, "ALIASES_NOT_ALLOWED")
}

// Some servers read a body on GET too; it cannot be checked, so it is refused.
func TestGraphQLRequest_GETWithBodyRejected(t *testing.T) {
	u := newGraphQLUpstream(t)
	req := httptest.NewRequest(http.MethodGet, "/graphql?query="+url.QueryEscape(`{ Person { IIN } }`),
		strings.NewReader(jsonBody(t, `{ Person { x: IIN } }`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	graphqlHandler(t, u).ServeHTTP(rec, req)
	assertRejected(t, rec, u, http.StatusBadRequest, "UNSUPPORTED_REQUEST")
}
