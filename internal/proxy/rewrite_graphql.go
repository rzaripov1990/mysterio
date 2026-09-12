package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"

	"mysterio/internal/masker"
)

// maxEnvelopeBodyBytes caps the upstream excerpt embedded in the error
// envelope. The excerpt is masked BEFORE truncation, so cutting it can never
// expose the tail of a value the masker would have replaced.
const maxEnvelopeBodyBytes = 2048

// GraphQLMaskers holds the two maskers the /graphql route needs.
type GraphQLMaskers struct {
	// Doc masks the GraphQL JSON document, built from the rules file's
	// graphql block alone.
	Doc *masker.Masker
	// Text masks the excerpt of a non-JSON upstream body embedded in the
	// error envelope. That excerpt is free text (an ingress error page, a
	// plain-text 503), not a GraphQL document, so it is run through the
	// global log rules — the graphql block has no regex mechanism and its
	// key patterns only match the "key":"value" JSON form. May be nil, in
	// which case only Doc is applied.
	Text *masker.Masker
}

// MaskGraphQLResponseBody masks a GraphQL response with the rules from the
// rules file's graphql block. The whole document is walked by key name
// (data, errors, extensions alike) — GraphQL has no fixed log-line shape, so
// there is nothing narrower to target.
//
// The route contract is "always JSON": a body that does not parse as JSON
// (an ingress HTML error page, plain text, an empty body) is replaced by a
// GraphQL-shaped error envelope carrying the upstream status and a masked,
// truncated excerpt of what the upstream actually sent.
//
// Returns (body, changed, err).
func MaskGraphQLResponseBody(body []byte, mk GraphQLMaskers, upstreamStatus int) ([]byte, bool, error) {
	m := mk.Doc
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return graphQLErrorEnvelope(body, mk, upstreamStatus)
	}
	if _, ok := root.(map[string]any); !ok {
		// A bare scalar or array is not a GraphQL response document.
		return graphQLErrorEnvelope(body, mk, upstreamStatus)
	}

	if !m.WalkAndMask(root) {
		return body, false, nil
	}
	out, err := json.Marshal(root)
	if err != nil {
		return body, false, err
	}
	return out, true, nil
}

func graphQLErrorEnvelope(body []byte, mk GraphQLMaskers, upstreamStatus int) ([]byte, bool, error) {
	excerpt := mk.Doc.Apply(string(body))
	if mk.Text != nil {
		excerpt = mk.Text.Apply(excerpt)
	}
	// Masked before truncation, so cutting the excerpt can never expose the
	// tail of a value the maskers would have replaced.
	excerpt = truncateUTF8(excerpt, maxEnvelopeBodyBytes)
	envelope := map[string]any{
		"data": nil,
		"errors": []any{
			map[string]any{
				"message": "upstream returned a non-JSON response",
				"extensions": map[string]any{
					"upstream_status": upstreamStatus,
					"body":            excerpt,
				},
			},
		},
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		return nil, false, fmt.Errorf("marshal graphql error envelope: %w", err)
	}
	return out, true, nil
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
