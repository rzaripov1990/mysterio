package proxy

import (
	"encoding/json"

	"mystrio/internal/masker"
)

// MaskResponseBody masks log lines in Loki query JSON (data.result[].values[][1]).
// Returns (body, changed, err). If the body is not a query result shape, returns the
// original body and changed=false.
func MaskResponseBody(body []byte, m *masker.Masker) ([]byte, bool, error) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return body, false, err
	}
	data, ok := root["data"].(map[string]any)
	if !ok {
		return body, false, nil
	}
	result, ok := data["result"].([]any)
	if !ok || len(result) == 0 {
		return body, false, nil
	}

	changed := false
	for _, item := range result {
		stream, ok := item.(map[string]any)
		if !ok {
			continue
		}
		values, ok := stream["values"].([]any)
		if !ok {
			continue
		}
		for _, pair := range values {
			row, ok := pair.([]any)
			if !ok || len(row) < 2 {
				continue
			}
			line, ok := row[1].(string)
			if !ok {
				continue
			}
			masked := m.Apply(line)
			if masked != line {
				row[1] = masked
				changed = true
			}
		}
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
