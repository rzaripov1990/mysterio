package proxy

import (
	"bytes"
	"encoding/json"
	"strings"

	"mysterio/internal/masker"
)

// MaskElasticResponseBody masks _source in Elasticsearch _search/_msearch bodies.
//
// messageField mirrors Grafana's "Message field name":
//   - "" (default): whole _source is the log message — json_keys on the object,
//     then Apply (regex) on every string field;
//   - "log" (etc.): json_keys on the object, Apply only on that field.
//
// Returns (body, changed, err). Shapes without hits.hits are unchanged.
func MaskElasticResponseBody(body []byte, m *masker.Masker, messageField string) ([]byte, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		return body, false, err
	}

	messageField = strings.TrimSpace(messageField)
	changed := false
	if responses, ok := root["responses"].([]any); ok {
		for _, r := range responses {
			resp, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if maskElasticHits(resp, m, messageField) {
				changed = true
			}
		}
	} else {
		changed = maskElasticHits(root, m, messageField)
	}

	if !changed {
		return body, false, nil
	}
	out, err := json.Marshal(root)
	if err != nil {
		return body, false, err
	}
	return out, true, nil
}

func maskElasticHits(resp map[string]any, m *masker.Masker, messageField string) bool {
	hitsWrap, ok := resp["hits"].(map[string]any)
	if !ok {
		return false
	}
	hits, ok := hitsWrap["hits"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, h := range hits {
		hit, ok := h.(map[string]any)
		if !ok {
			continue
		}
		src, ok := hit["_source"].(map[string]any)
		if !ok {
			continue
		}
		if maskElasticSource(src, m, messageField) {
			changed = true
		}
	}
	return changed
}

func maskElasticSource(src map[string]any, m *masker.Masker, messageField string) bool {
	// Always mask structured json_keys / embedded JSON in the document.
	changed := m.WalkAndMask(src)

	if messageField == "" {
		// Grafana default: message is the whole _source — Apply on all strings.
		if m.ApplyStrings(src) {
			changed = true
		}
		return changed
	}

	raw, ok := src[messageField]
	if !ok {
		return changed
	}
	s, ok := raw.(string)
	if !ok {
		return changed
	}
	masked := m.Apply(s)
	if masked != s {
		src[messageField] = masked
		changed = true
	}
	return changed
}
