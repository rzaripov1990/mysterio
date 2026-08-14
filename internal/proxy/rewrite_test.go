package proxy_test

import (
	"bytes"
	"encoding/json"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/proxy"
)

func TestMaskResponseBody_QueryRange(t *testing.T) {
	content := `
json_keys:
  - name: iin
    keys: [iin]
    replace: "************"
`
	rules, err := config.LoadRules([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	m, err := masker.New(rules, nil)
	if err != nil {
		t.Fatal(err)
	}

	in := []byte(`{
	  "status":"success",
	  "data":{
	    "resultType":"streams",
	    "result":[{
	      "stream":{"k8s_app":"bpf-msa/x"},
	      "values":[["123","{\"iin\":\"999\"}"]]
	    }]
	  }
	}`)
	out, changed, err := proxy.MaskResponseBody(in, m)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}

	var root map[string]any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	data := root["data"].(map[string]any)
	result := data["result"].([]any)
	stream := result[0].(map[string]any)
	labels := stream["stream"].(map[string]any)
	if labels["k8s_app"] != "bpf-msa/x" {
		t.Fatalf("labels mutated: %+v", labels)
	}
	values := stream["values"].([]any)
	row := values[0].([]any)
	if row[0] != "123" {
		t.Fatalf("timestamp mutated: %v", row[0])
	}
	line := row[1].(string)
	var lineObj map[string]any
	if err := json.Unmarshal([]byte(line), &lineObj); err != nil {
		t.Fatal(err)
	}
	if lineObj["iin"] != "************" {
		t.Fatalf("iin not masked: %s", line)
	}
	// Grafana is sensitive to a missing/late resultType after remarshal.
	if data["resultType"] != "streams" {
		t.Fatalf("resultType=%v want streams", data["resultType"])
	}
	if !bytes.Contains(out, []byte(`"resultType":"streams"`)) {
		t.Fatalf("masked body missing resultType literal: %s", out)
	}
	// resultType must appear before the result array in the serialized form.
	rtAt := bytes.Index(out, []byte(`"resultType"`))
	resAt := bytes.Index(out, []byte(`"result":[`))
	if rtAt < 0 || resAt < 0 || rtAt > resAt {
		t.Fatalf("resultType must be emitted before result array (rt=%d result=%d) body=%s", rtAt, resAt, out)
	}
}

func TestMaskResponseBody_NoResultPassthrough(t *testing.T) {
	m, err := masker.New(config.Rules{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	in := []byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`)
	out, changed, err := proxy.MaskResponseBody(in, m)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected unchanged")
	}
	if string(out) != string(in) {
		t.Fatalf("body rewritten unexpectedly")
	}
}
