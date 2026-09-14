package masker_test

import (
	"strings"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/token"
)

func newGraphQL(t *testing.T, rulesYAML string) *masker.GraphQL {
	t.Helper()
	rules, err := config.LoadRules([]byte(rulesYAML))
	if err != nil {
		t.Fatal(err)
	}
	g, err := masker.NewGraphQL(rules.GraphQL.JSONKeys, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func maskDoc(t *testing.T, g *masker.GraphQL, body string) (string, bool) {
	t.Helper()
	out, changed, err := g.MaskDocument([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return string(out), changed
}

const personResponse = `{
  "data": {
    "Person": [
      {
        "FIRSTNAME": {"RU": "РАВИЛЬ", "KZ": "РАВИЛЬ", "EN": "RAVIL"},
        "LASTNAME": {"RU": "ЗАРИПОВ", "KZ": "ЗАРИПОВ", "EN": "ZARIPOV"},
        "IIN": "900621300906",
        "MIDDLENAME": {"RU": "ХАСАНОВИЧ", "KZ": "ХАСАНОВИЧ", "EN": null}
      }
    ]
  }
}`

func TestGraphQL_PersonExample_StructureAndOrderPreserved(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: names
      keys: [FIRSTNAME, LASTNAME, MIDDLENAME]
      keep_first: 1
      replace: "***"
    - name: iin
      keys: [IIN]
      keep_first: 4
      keep_last: 2
      replace: "******"
`)
	out, changed := maskDoc(t, g, personResponse)
	want := `{"data":{"Person":[{` +
		`"FIRSTNAME":{"RU":"Р***","KZ":"Р***","EN":"R***"},` +
		`"LASTNAME":{"RU":"З***","KZ":"З***","EN":"Z***"},` +
		`"IIN":"9006******06",` +
		`"MIDDLENAME":{"RU":"Х***","KZ":"Х***","EN":null}}]}}`
	if out != want {
		t.Fatalf("got\n%s\nwant\n%s", out, want)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
}

func TestGraphQL_PathSelectsSingleNestedField(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: ru
      keys: [FIRSTNAME.RU]
      keep_first: 1
      replace: "***"
`)
	out, _ := maskDoc(t, g, `{"data":{"FIRSTNAME":{"RU":"РАВИЛЬ","KZ":"РАВИЛЬ","EN":"RAVIL"},"LASTNAME":{"RU":"ЗАРИПОВ"}}}`)
	want := `{"data":{"FIRSTNAME":{"RU":"Р***","KZ":"РАВИЛЬ","EN":"RAVIL"},"LASTNAME":{"RU":"ЗАРИПОВ"}}}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_WildcardMatchesChildrenOnly(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: names
      keys: [FIRSTNAME.*]
      replace: "***"
`)
	out, _ := maskDoc(t, g, `{"a":{"FIRSTNAME":{"RU":"X","EN":"Y"}},"b":{"FIRSTNAME":"PLAIN"}}`)
	want := `{"a":{"FIRSTNAME":{"RU":"***","EN":"***"}},"b":{"FIRSTNAME":"PLAIN"}}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_PlainKeyMasksStringOrWholeSubtree(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: names
      keys: [FIRSTNAME]
      replace: "***"
`)
	out, _ := maskDoc(t, g, `{"a":{"FIRSTNAME":{"RU":"X","deep":{"v":"Y","n":null,"b":true}}},"b":{"FIRSTNAME":"PLAIN"}}`)
	want := `{"a":{"FIRSTNAME":{"RU":"***","deep":{"v":"***","n":null,"b":true}}},"b":{"FIRSTNAME":"***"}}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_MostSpecificRuleWins(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: whole
      keys: [FIRSTNAME]
      replace: "###"
    - name: children
      keys: [FIRSTNAME.*]
      replace: "@@@"
    - name: ru
      keys: [FIRSTNAME.RU]
      keep_first: 1
      replace: "***"
    - name: person
      keys: [Person.FIRSTNAME]
      replace: "%%%"
`)
	out, _ := maskDoc(t, g, `{"Person":{"FIRSTNAME":{"RU":"РАВИЛЬ","KZ":"РАВИЛЬ","X":{"Y":"Z"}}}}`)
	// RU: FIRSTNAME.RU (anchored at the leaf, two literal segments).
	// KZ: FIRSTNAME.* (anchored at the leaf) beats the container rules.
	// X.Y: X is matched by FIRSTNAME.*, which is deeper than Person.FIRSTNAME.
	want := `{"Person":{"FIRSTNAME":{"RU":"Р***","KZ":"@@@","X":{"Y":"@@@"}}}}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_ArraysAreTransparentInPaths(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: iin
      keys: [Person.IIN]
      replace: "***"
    - name: phones
      keys: [phones]
      replace: "***"
`)
	out, _ := maskDoc(t, g, `{"data":{"Person":[{"IIN":"1"},{"IIN":"2"}],"IIN":"top","phones":["+7701","+7702"]}}`)
	want := `{"data":{"Person":[{"IIN":"***"},{"IIN":"***"}],"IIN":"top","phones":["***","***"]}}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_Numbers(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: balance
      keys: [BALANCE]
      replace_number: 0
    - name: amount
      keys: [AMOUNT]
      replace: "***"
    - name: precise
      keys: [PRECISE]
      replace_number: -1.00
`)
	out, _ := maskDoc(t, g, `{"BALANCE":12345.67,"AMOUNT":42,"PRECISE":1e3,"OTHER":1.50}`)
	want := `{"BALANCE":0,"AMOUNT":null,"PRECISE":-1.00,"OTHER":1.50}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_PartialMask_ShortValueFullyReplaced(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: iin
      keys: [IIN]
      keep_first: 4
      keep_last: 2
      replace: "******"
`)
	out, _ := maskDoc(t, g, `{"a":{"IIN":"123456"},"b":{"IIN":"1234567"},"c":{"IIN":""}}`)
	want := `{"a":{"IIN":"******"},"b":{"IIN":"1234******67"},"c":{"IIN":"******"}}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_MatchedNullAndBoolUntouched(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: x
      keys: [IIN, FLAG]
      replace: "***"
`)
	out, changed := maskDoc(t, g, `{"IIN":null,"FLAG":false}`)
	if out != `{"IIN":null,"FLAG":false}` || changed {
		t.Fatalf("got %s changed=%v", out, changed)
	}
}

func TestGraphQL_NoMatch_ReturnsOriginalBody(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: x
      keys: [IIN]
      replace: "***"
`)
	body := "{\n  \"data\": {\"ping\": \"pong\"}\n}"
	out, changed := maskDoc(t, g, body)
	if changed || out != body {
		t.Fatalf("got %q changed=%v", out, changed)
	}
}

func TestGraphQL_KeysAndStringsEscapedCorrectly(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: x
      keys: [IIN]
      replace: "***"
`)
	out, _ := maskDoc(t, g, `{"q\"k":"<a & b>\n","IIN":"1","u":"\u00e9"}`)
	want := `{"q\"k":"<a & b>\n","IIN":"***","u":"é"}`
	if out != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
}

func TestGraphQL_EmbeddedJSONStringMasked(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: x
      keys: [IIN]
      replace: "***"
`)
	out, _ := maskDoc(t, g, `{"errors":[{"message":"bad input {\"IIN\":\"900621300906\"}"}]}`)
	if strings.Contains(out, "900621300906") {
		t.Fatalf("embedded JSON not masked: %s", out)
	}
}

func TestGraphQL_HMACReplacement(t *testing.T) {
	rules, err := config.LoadRules([]byte(`
graphql:
  json_keys:
    - name: iin
      keys: [IIN]
      replace: "{hmac}"
      normalize: digits
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := masker.NewGraphQL(rules.GraphQL.JSONKeys, nil); err == nil {
		t.Fatal("expected error for {hmac} without a tokenizer")
	}
	g, err := masker.NewGraphQL(rules.GraphQL.JSONKeys, token.New([]byte("0123456789abcdef0123456789abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := maskDoc(t, g, `{"IIN":"900621300906"}`)
	if strings.Contains(out, "900621300906") || !strings.Contains(out, `"IIN":"~`) {
		t.Fatalf("expected hmac token, got %s", out)
	}
}

func TestGraphQL_InvalidDocument_Error(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: x
      keys: [IIN]
      replace: "***"
`)
	for _, body := range []string{``, `[1]`, `"s"`, `{"a":`, `<html>`} {
		if _, _, err := g.MaskDocument([]byte(body)); err == nil {
			t.Fatalf("expected error for %q", body)
		}
	}
}

func TestGraphQL_ApplyText_MasksKeyValueText(t *testing.T) {
	g := newGraphQL(t, `
graphql:
  json_keys:
    - name: ru
      keys: [FIRSTNAME.RU]
      keep_first: 1
      replace: "***"
`)
	out := g.ApplyText(`ingress error: {"RU":"РАВИЛЬ"} broken`)
	if strings.Contains(out, "РАВИЛЬ") {
		t.Fatalf("text excerpt leaked: %s", out)
	}
}
