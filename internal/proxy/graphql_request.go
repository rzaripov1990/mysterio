package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

const (
	// maxGraphQLRequestBytes caps the request body buffered for inspection.
	maxGraphQLRequestBytes = 1 << 20
	// maxGraphQLQueryTokens bounds parser work and nesting depth for a single
	// query, so a pathological document cannot exhaust CPU or stack.
	maxGraphQLQueryTokens = 15000
)

// graphQLRequestError is a request refused before it reaches the upstream.
type graphQLRequestError struct {
	status  int
	code    string
	message string
}

func (e *graphQLRequestError) Error() string { return e.code + ": " + e.message }

func rejectRequest(status int, code, format string, args ...any) *graphQLRequestError {
	return &graphQLRequestError{status: status, code: code, message: fmt.Sprintf(format, args...)}
}

// guardGraphQLRequest refuses GraphQL requests whose response could not be
// masked reliably. Masking rules match response keys, and an alias
// (hackIIN: IIN) lets the caller rename those keys — so every query must be
// parsed and must not contain aliases. A request that cannot be checked
// (hash-only persisted query, unparseable, unsupported encoding) is refused
// too: letting it through would reopen the same bypass. Websocket upgrades
// are refused because subscription frames are never masked.
func guardGraphQLRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := checkGraphQLRequest(r); err != nil {
			slog.Warn("graphql request rejected",
				"method", r.Method,
				"path", r.URL.Path,
				"code", err.code,
				"reason", err.message,
			)
			writeGraphQLRequestError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func checkGraphQLRequest(r *http.Request) *graphQLRequestError {
	if r.Header.Get("Upgrade") != "" {
		return rejectRequest(http.StatusBadRequest, "WEBSOCKET_NOT_ALLOWED",
			"websocket subscriptions are not supported")
	}
	// Some servers read ?query= on any method, and some bind parameters
	// case-insensitively, so every copy under any casing is checked.
	var queries []string
	for k, vs := range r.URL.Query() {
		if isQueryKey(k) {
			queries = append(queries, vs...)
		}
	}

	switch r.Method {
	case http.MethodOptions:
		// CORS preflight: no query, nothing executes upstream.
		return nil
	case http.MethodGet, http.MethodHead:
		// A body on GET cannot be checked, yet some servers would read it.
		if r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
			return rejectRequest(http.StatusBadRequest, "UNSUPPORTED_REQUEST",
				"a %s request must not have a body", r.Method)
		}
	case http.MethodPost:
		fromBody, err := readGraphQLBody(r)
		if err != nil {
			return err
		}
		queries = append(queries, fromBody...)
	default:
		return rejectRequest(http.StatusMethodNotAllowed, "UNSUPPORTED_REQUEST",
			"method %s is not supported", r.Method)
	}

	if len(queries) == 0 {
		return rejectRequest(http.StatusBadRequest, "QUERY_REQUIRED",
			"the request must carry the query text (persisted queries by hash are not supported)")
	}
	for _, q := range queries {
		if err := checkQuery(q); err != nil {
			return err
		}
	}
	return nil
}

// readGraphQLBody buffers a POST body, restores it for the proxy, and returns
// the query of every operation in it (one, or several for a batch).
func readGraphQLBody(r *http.Request) ([]string, *graphQLRequestError) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, rejectRequest(http.StatusBadRequest, "UNSUPPORTED_REQUEST",
			"Content-Type must be application/json")
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxGraphQLRequestBytes))
	_ = r.Body.Close()
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, rejectRequest(http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE",
				"request body exceeds %d bytes", maxGraphQLRequestBytes)
		}
		return nil, rejectRequest(http.StatusBadRequest, "INVALID_REQUEST", "read request body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }

	queries, err := queriesFromJSON(body)
	if err != nil {
		var reqErr *graphQLRequestError
		if errors.As(err, &reqErr) {
			return nil, reqErr
		}
		return nil, rejectRequest(http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body: %v", err)
	}
	return queries, nil
}

// queriesFromJSON extracts "query" from a request object or from each object
// of a batch array. It walks tokens instead of unmarshalling into a struct:
// JSON parsers disagree on duplicate keys (first wins, last wins) and on key
// casing (Jackson is exact, .NET and Go structs fold case), so a request
// carrying more than one copy of "query" under any casing is refused — the
// query checked here must be the one the upstream runs.
func queriesFromJSON(body []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	var queries []string
	switch tok {
	case json.Delim('{'):
		q, err := queryFromObject(dec)
		if err != nil {
			return nil, err
		}
		queries = append(queries, q)
	case json.Delim('['):
		for dec.More() {
			if t, err := dec.Token(); err != nil {
				return nil, err
			} else if t != json.Delim('{') {
				return nil, errors.New("batch element is not an object")
			}
			q, err := queryFromObject(dec)
			if err != nil {
				return nil, err
			}
			queries = append(queries, q)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		if len(queries) == 0 {
			return nil, errors.New("empty batch")
		}
	default:
		return nil, errors.New("body is not a JSON object or array")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("unexpected data after the JSON body")
	}
	return queries, nil
}

// queryFromObject reads one request object after its opening '{'.
func queryFromObject(dec *json.Decoder) (string, error) {
	seen := make(map[string]bool)
	query := ""
	queryKeys := 0
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", err
		}
		key := t.(string)
		if seen[key] {
			return "", fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", err
		}
		if !isQueryKey(key) {
			continue
		}
		if queryKeys++; queryKeys > 1 {
			return "", fmt.Errorf("more than one query key (%q)", key)
		}
		if string(raw) == "null" {
			continue
		}
		if err := json.Unmarshal(raw, &query); err != nil {
			return "", errors.New(`"query" must be a string`)
		}
	}
	if _, err := dec.Token(); err != nil {
		return "", err
	}
	if query == "" {
		return "", rejectRequest(http.StatusBadRequest, "QUERY_REQUIRED",
			"the request must carry the query text (persisted queries by hash are not supported)")
	}
	return query, nil
}

func isQueryKey(k string) bool { return strings.EqualFold(k, "query") }

func checkQuery(query string) *graphQLRequestError {
	doc, err := parser.ParseQueryWithTokenLimit(&ast.Source{Input: query}, maxGraphQLQueryTokens)
	if err != nil {
		return rejectRequest(http.StatusBadRequest, "GRAPHQL_PARSE_FAILED", "%v", err)
	}
	if f := findAlias(doc); f != nil {
		return rejectRequest(http.StatusBadRequest, "ALIASES_NOT_ALLOWED",
			"aliases are not allowed (%s: %s)", f.Alias, f.Name)
	}
	return nil
}

// findAlias returns the first field whose response key differs from its name,
// in any operation or fragment definition (used or not).
func findAlias(doc *ast.QueryDocument) *ast.Field {
	for _, op := range doc.Operations {
		if f := aliasIn(op.SelectionSet); f != nil {
			return f
		}
	}
	for _, fr := range doc.Fragments {
		if f := aliasIn(fr.SelectionSet); f != nil {
			return f
		}
	}
	return nil
}

func aliasIn(set ast.SelectionSet) *ast.Field {
	for _, sel := range set {
		switch s := sel.(type) {
		case *ast.Field:
			if s.Alias != s.Name {
				return s
			}
			if f := aliasIn(s.SelectionSet); f != nil {
				return f
			}
		case *ast.InlineFragment:
			if f := aliasIn(s.SelectionSet); f != nil {
				return f
			}
		}
		// *ast.FragmentSpread points at a definition findAlias checks itself.
	}
	return nil
}

func writeGraphQLRequestError(w http.ResponseWriter, e *graphQLRequestError) {
	body, _ := json.Marshal(map[string]any{
		"errors": []any{map[string]any{
			"message":    e.message,
			"extensions": map[string]any{"code": e.code},
		}},
	})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(e.status)
	_, _ = w.Write(body)
}
