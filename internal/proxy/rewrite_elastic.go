package proxy

import (
	"encoding/json"

	"mystrio/internal/masker"
)

// MaskElasticResponseBody masks _source fields (by JSON key, same rules
// used for Loki) in Elasticsearch _search and _msearch response bodies.
// Returns (body, changed, err). Shapes without a "hits.hits" array
// (either at the top level or inside each "responses[]" entry for
// _msearch) are returned unchanged — callers are expected to only invoke
// this for _search/_msearch responses in the first place.
func MaskElasticResponseBody(body []byte, m *masker.Masker) ([]byte, bool, error) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return body, false, err
	}

	changed := false
	if responses, ok := root["responses"].([]any); ok {
		for _, r := range responses {
			resp, ok := r.(map[string]any)
			if !ok {
				continue
			}
			if maskElasticHits(resp, m) {
				changed = true
			}
		}
	} else {
		changed = maskElasticHits(root, m)
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

func maskElasticHits(resp map[string]any, m *masker.Masker) bool {
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
		if m.WalkAndMask(src) {
			changed = true
		}
	}
	return changed
}
