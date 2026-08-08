package masker_test

import (
	"encoding/json"
	"strings"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
)

func mustLoad(t *testing.T, content []byte) config.Rules {
	t.Helper()
	rules, err := config.LoadRules(content)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func rulesForTest(t *testing.T) config.Rules {
	t.Helper()
	return mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin, biin]
    replace: "************"
regex:
  - name: email
    pattern: '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    replace: "***@***"`))
}

func TestApply_FlatJSONKey(t *testing.T) {
	m := masker.New(rulesForTest(t))
	got := m.Apply(`{"iin":"12313132123123"}`)
	assertJSONEqual(t, got, `{"iin":"************"}`)
}

func TestApply_NestedJSONKey(t *testing.T) {
	m := masker.New(rulesForTest(t))
	got := m.Apply(`{"data":[{"iin":"716237816371637"}]}`)
	assertJSONEqual(t, got, `{"data":[{"iin":"************"}]}`)
}

func TestApply_NonJSONRegex(t *testing.T) {
	m := masker.New(rulesForTest(t))
	got := m.Apply(`user email is a@b.com ok`)
	if got != `user email is ***@*** ok` {
		t.Fatalf("got %q", got)
	}
}

func TestApply_UnrelatedJSONKeyUntouched(t *testing.T) {
	m := masker.New(rulesForTest(t))
	got := m.Apply(`{"name":"alice","iin":"123"}`)
	assertJSONEqual(t, got, `{"name":"alice","iin":"************"}`)
}

func TestApply_SQLLogWithEmbeddedJSON(t *testing.T) {
	// json_keys alone must mask biin/iin inside SQL / non-JSON lines
	m := masker.New(mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin, biin]
    replace: "************"
`)))
	line := `UPDATE "log_request_responses" SET "request_body"='{"susnRequest":{"params":[{"biin":"890501402951"}]}}',"response_body"='{"report":{"iin":"890501402951"},"reportData":"{\"iin\":\"890501402951\"}"}'`
	out := m.Apply(line)
	t.Log(out)
	if strings.Contains(out, `"biin":"890501402951"`) {
		t.Fatal("biin not masked")
	}
	if strings.Contains(out, `"iin":"890501402951"`) {
		t.Fatal("iin not masked")
	}
	if strings.Contains(out, `\"iin\":\"890501402951\"`) {
		t.Fatal("escaped iin not masked")
	}
}

func TestApply_NestedJSONStringValue(t *testing.T) {
	m := masker.New(rulesForTest(t))
	got := m.Apply(`{"reportData":"{\"iin\":\"890501402951\"}"}`)
	if strings.Contains(got, "890501402951") {
		t.Fatalf("nested JSON string not masked: %s", got)
	}
}

func TestApply_DebugMessageWithURLAndJSON(t *testing.T) {
	m := masker.New(mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin, biin, iinBin]
    replace: "************"
`)))
	line := `{"level":"DEBUG","message":"https://svc.example/api/esi/bvuiethree/secure/report {\"data\":[{\"report\":{\"individualEntrepreneurInfo\":{\"iinBin\":\"680000005058\",\"nameRu\":\"ИП ТУРЫКБАЕВА\"}}}]}"}`
	got := m.Apply(line)
	t.Log(got)
	if strings.Contains(got, "680000005058") {
		t.Fatalf("iinBin not masked: %s", got)
	}
	if !strings.Contains(got, `"iinBin":"************"`) && !strings.Contains(got, `\"iinBin\":\"************\"`) {
		t.Fatalf("expected masked iinBin in output: %s", got)
	}
}

func TestWalkAndMask_MasksKey(t *testing.T) {
	m := masker.New(rulesForTest(t))
	v := map[string]any{"iin": "12313132123123", "name": "alice"}
	changed := m.WalkAndMask(v)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if v["iin"] != "************" {
		t.Fatalf("iin not masked: %+v", v)
	}
	if v["name"] != "alice" {
		t.Fatalf("unrelated key mutated: %+v", v)
	}
}

func TestWalkAndMask_NoChange(t *testing.T) {
	m := masker.New(rulesForTest(t))
	v := map[string]any{"name": "alice"}
	changed := m.WalkAndMask(v)
	if changed {
		t.Fatal("expected changed=false")
	}
	if v["name"] != "alice" {
		t.Fatalf("value mutated unexpectedly: %+v", v)
	}
}

func TestWalkAndMask_Nested(t *testing.T) {
	m := masker.New(rulesForTest(t))
	v := map[string]any{
		"hits": []any{
			map[string]any{"biin": "890501402951"},
		},
	}
	if !m.WalkAndMask(v) {
		t.Fatal("expected changed=true")
	}
	hits := v["hits"].([]any)
	hit := hits[0].(map[string]any)
	if hit["biin"] != "************" {
		t.Fatalf("nested biin not masked: %+v", hit)
	}
}

func assertJSONEqual(t *testing.T, got, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		t.Fatalf("got not JSON: %v (%s)", err, got)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("want not JSON: %v", err)
	}
	gb, _ := json.Marshal(g)
	wb, _ := json.Marshal(w)
	if string(gb) != string(wb) {
		t.Fatalf("got %s want %s", gb, wb)
	}
}
