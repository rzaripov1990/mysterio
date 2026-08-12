package proxy

import (
	"bytes"
	"encoding/json"

	"mysterio/internal/masker"
)

// MaskResponseBody masks log lines in Loki query JSON (data.result[].values[][1]).
// Returns (body, changed, err). If the body is not a query result shape, returns the
// original body and changed=false.
//
// When rewriting, resultType/status/stats are preserved via json.RawMessage and the
// envelope is re-emitted with a stable field order (status → data.resultType →
// data.result → data.stats). Remarshaling the whole document as map[string]any
// reorders keys and has been observed to confuse some Grafana Loki clients
// ("unknown result type: ").
func MaskResponseBody(body []byte, m *masker.Masker) ([]byte, bool, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return body, false, err
	}
	dataRaw, ok := root["data"]
	if !ok {
		return body, false, nil
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		return body, false, nil
	}
	resultRaw, ok := data["result"]
	if !ok {
		return body, false, nil
	}
	var result []any
	if err := json.Unmarshal(resultRaw, &result); err != nil || len(result) == 0 {
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

	newResult, err := json.Marshal(result)
	if err != nil {
		return body, false, err
	}

	// Rebuild with stable key order expected by Grafana's Loki client.
	var buf bytes.Buffer
	buf.WriteByte('{')
	if st, ok := root["status"]; ok {
		buf.WriteString(`"status":`)
		buf.Write(st)
		buf.WriteByte(',')
	}
	buf.WriteString(`"data":{`)
	if rt, ok := data["resultType"]; ok {
		buf.WriteString(`"resultType":`)
		buf.Write(rt)
		buf.WriteByte(',')
	} else {
		// Defensive: never emit a streams payload without resultType.
		buf.WriteString(`"resultType":"streams",`)
	}
	buf.WriteString(`"result":`)
	buf.Write(newResult)
	if stats, ok := data["stats"]; ok {
		buf.WriteString(`,"stats":`)
		buf.Write(stats)
	}
	buf.WriteString(`}`)
	// Preserve any other top-level fields (error, warnings, …) after data.
	for k, v := range root {
		if k == "status" || k == "data" {
			continue
		}
		buf.WriteByte(',')
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), true, nil
}
