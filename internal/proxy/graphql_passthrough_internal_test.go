package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
)

// A websocket upgrade (GraphQL subscriptions) reaches ModifyResponse with the
// Upgrade header still present — ReverseProxy runs the hook for 101 responses
// before handleUpgradeResponse and before hop-by-hop headers are stripped.
// Such a response must leave completely untouched: rewriting its body or
// Content-Type would corrupt the handshake.
func TestModifyGraphQLResponse_WebsocketUpgrade_Untouched(t *testing.T) {
	m, err := masker.New(config.Rules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header: http.Header{
			"Upgrade":      []string{"websocket"},
			"Connection":   []string{"Upgrade"},
			"Content-Type": []string{"text/plain"},
		},
		Body: io.NopCloser(strings.NewReader("")),
	}

	if err := modifyGraphQLResponse(resp, config.Config{MaxResponseBytes: 1 << 20}, GraphQLMaskers{Doc: m}); err != nil {
		t.Fatal(err)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "text/plain" {
		t.Fatalf("websocket upgrade must keep its Content-Type, got %q", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("websocket upgrade body rewritten: %q", body)
	}
}
