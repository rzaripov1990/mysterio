package masker_test

import (
	"encoding/json"
	"strings"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/token"
)

func mustLoad(t *testing.T, content []byte) config.Rules {
	t.Helper()
	rules, err := config.LoadRules(content)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func mustMasker(t *testing.T, rules config.Rules) *masker.Masker {
	t.Helper()
	m, err := masker.New(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
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
	m := mustMasker(t, rulesForTest(t))
	got := m.Apply(`{"iin":"12313132123123"}`)
	assertJSONEqual(t, got, `{"iin":"************"}`)
}

func TestApply_NestedJSONKey(t *testing.T) {
	m := mustMasker(t, rulesForTest(t))
	got := m.Apply(`{"data":[{"iin":"716237816371637"}]}`)
	assertJSONEqual(t, got, `{"data":[{"iin":"************"}]}`)
}

func TestApply_NonJSONRegex(t *testing.T) {
	m := mustMasker(t, rulesForTest(t))
	got := m.Apply(`user email is a@b.com ok`)
	if got != `user email is ***@*** ok` {
		t.Fatalf("got %q", got)
	}
}

func TestApply_UnrelatedJSONKeyUntouched(t *testing.T) {
	m := mustMasker(t, rulesForTest(t))
	got := m.Apply(`{"name":"alice","iin":"123"}`)
	assertJSONEqual(t, got, `{"name":"alice","iin":"************"}`)
}

func TestApply_SQLLogWithEmbeddedJSON(t *testing.T) {
	// json_keys alone must mask biin/iin inside SQL / non-JSON lines
	m := mustMasker(t, mustLoad(t, []byte(`
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
	m := mustMasker(t, rulesForTest(t))
	got := m.Apply(`{"reportData":"{\"iin\":\"890501402951\"}"}`)
	if strings.Contains(got, "890501402951") {
		t.Fatalf("nested JSON string not masked: %s", got)
	}
}

func TestApply_DebugMessageWithURLAndJSON(t *testing.T) {
	m := mustMasker(t, mustLoad(t, []byte(`
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
	m := mustMasker(t, rulesForTest(t))
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
	m := mustMasker(t, rulesForTest(t))
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
	m := mustMasker(t, rulesForTest(t))
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

const testHMACKey = "0123456789abcdef0123456789abcdef"

func hmacTok(t *testing.T) *token.Tokenizer {
	t.Helper()
	return token.New([]byte(testHMACKey))
}

func TestApply_HMAC_JSONStringAndNumber(t *testing.T) {
	rules := mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
    normalize: digits
`))
	m, err := masker.New(rules, hmacTok(t))
	if err != nil {
		t.Fatal(err)
	}
	s := m.Apply(`{"iin":"890501402951"}`)
	n := m.Apply(`{"iin":890501402951}`)
	if !strings.Contains(s, `~nAqddoqkCK8`) {
		t.Fatalf("string: %s", s)
	}
	if !strings.Contains(n, `~nAqddoqkCK8`) {
		t.Fatalf("number: %s", n)
	}
}

func TestApply_HMAC_JSONKeysAndRegexSameToken(t *testing.T) {
	rules := mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
    normalize: digits
regex:
  - name: bare
    pattern: '\b\d{12}\b'
    replace: "{hmac}"
    normalize: digits
`))
	m, err := masker.New(rules, hmacTok(t))
	if err != nil {
		t.Fatal(err)
	}
	jsonLine := m.Apply(`{"iin":"890501402951"}`)
	bare := m.Apply(`iin=890501402951`)
	if !strings.Contains(jsonLine, `~nAqddoqkCK8`) || !strings.Contains(bare, `~nAqddoqkCK8`) {
		t.Fatalf("json=%s bare=%s", jsonLine, bare)
	}
}

func TestApply_HMAC_IdempotentSecondPass(t *testing.T) {
	rules := mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
    normalize: digits
`))
	m, err := masker.New(rules, hmacTok(t))
	if err != nil {
		t.Fatal(err)
	}
	once := m.Apply(`{"iin":"890501402951"}`)
	twice := m.Apply(once)
	if once != twice {
		t.Fatalf("second pass changed: %s -> %s", once, twice)
	}
}

func TestApply_HMAC_SkipEmptyNullBoolAsterisks(t *testing.T) {
	rules := mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
`))
	m, err := masker.New(rules, hmacTok(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		`{"iin":""}`, `{"iin":null}`, `{"iin":true}`, `{"iin":"***"}`, `{"iin":"************"}`,
	} {
		got := m.Apply(in)
		if !strings.Contains(got, `"iin":"***"`) {
			t.Fatalf("expected *** for %s got %s", in, got)
		}
	}
}

func TestApply_HMAC_Group2(t *testing.T) {
	rules := mustLoad(t, []byte(`
regex:
  - name: named
    pattern: '"(k)"\s*:\s*"([^"]*)"'
    replace: '"${1}":"{hmac:$2}"'
    normalize: digits
`))
	m, err := masker.New(rules, hmacTok(t))
	if err != nil {
		t.Fatal(err)
	}
	got := m.Apply(`"k":"890501402951"`)
	if got != `"k":"~nAqddoqkCK8"` {
		t.Fatalf("got %q", got)
	}
}

func TestNew_HMACNilTokenizer_Error(t *testing.T) {
	rules := mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
`))
	if _, err := masker.New(rules, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestWalkAndMask_HMAC_SameAsApply(t *testing.T) {
	rules := mustLoad(t, []byte(`
json_keys:
  - name: iin
    keys: [iin]
    replace: "{hmac}"
    normalize: digits
`))
	m, err := masker.New(rules, hmacTok(t))
	if err != nil {
		t.Fatal(err)
	}
	v := map[string]any{"iin": "890501402951"}
	if !m.WalkAndMask(v) {
		t.Fatal("expected change")
	}
	if v["iin"] != "~nAqddoqkCK8" {
		t.Fatalf("walk: %+v", v)
	}
	got := m.Apply(`{"iin":"890501402951"}`)
	if !strings.Contains(got, `~nAqddoqkCK8`) {
		t.Fatalf("apply: %s", got)
	}
}
