package proxy_test

import (
	"encoding/json"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/proxy"
)

func elasticTestMasker(t *testing.T) *masker.Masker {
	t.Helper()
	rules, err := config.LoadRules([]byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "************"
`))
	if err != nil {
		t.Fatal(err)
	}
	return masker.New(rules)
}

func TestMaskElasticResponseBody_Search(t *testing.T) {
	m := elasticTestMasker(t)
	in := []byte(`{
	  "hits": {
	    "total": {"value": 1},
	    "hits": [
	      {"_index":"logs-1","_id":"1","_source":{"iin":"999888777666","message":"hello"}}
	    ]
	  }
	}`)
	out, changed, err := proxy.MaskElasticResponseBody(in, m)
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
	hits := root["hits"].(map[string]any)["hits"].([]any)
	src := hits[0].(map[string]any)["_source"].(map[string]any)
	if src["iin"] != "************" {
		t.Fatalf("iin not masked: %+v", src)
	}
	if src["message"] != "hello" {
		t.Fatalf("unrelated field mutated: %+v", src)
	}
}

func TestMaskElasticResponseBody_Msearch(t *testing.T) {
	m := elasticTestMasker(t)
	in := []byte(`{
	  "responses": [
	    {"hits":{"hits":[{"_source":{"iin":"111222333444"}}]}},
	    {"hits":{"hits":[{"_source":{"name":"alice"}}]}}
	  ]
	}`)
	out, changed, err := proxy.MaskElasticResponseBody(in, m)
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
	responses := root["responses"].([]any)
	src0 := responses[0].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)
	if src0["iin"] != "************" {
		t.Fatalf("iin not masked in first response: %+v", src0)
	}
	src1 := responses[1].(map[string]any)["hits"].(map[string]any)["hits"].([]any)[0].(map[string]any)["_source"].(map[string]any)
	if src1["name"] != "alice" {
		t.Fatalf("unrelated field mutated in second response: %+v", src1)
	}
}

func TestMaskElasticResponseBody_HitWithoutSource(t *testing.T) {
	m := elasticTestMasker(t)
	in := []byte(`{"hits":{"hits":[{"_index":"logs-1","_id":"1"}]}}`)
	out, changed, err := proxy.MaskElasticResponseBody(in, m)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected changed=false for hit without _source")
	}
	if string(out) != string(in) {
		t.Fatal("body rewritten unexpectedly")
	}
}

func TestMaskElasticResponseBody_NoHitsPassthrough(t *testing.T) {
	m := elasticTestMasker(t)
	in := []byte(`{"acknowledged":true}`)
	out, changed, err := proxy.MaskElasticResponseBody(in, m)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected changed=false")
	}
	if string(out) != string(in) {
		t.Fatal("body rewritten unexpectedly")
	}
}
