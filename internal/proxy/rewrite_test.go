package proxy_test

import (
	"encoding/json"
	"testing"

	config "mystrio/configs"
	"mystrio/internal/masker"
	"mystrio/internal/proxy"
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
	m := masker.New(rules)

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
}

func TestMaskResponseBody_NoResultPassthrough(t *testing.T) {
	m := masker.New(config.Rules{})
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
