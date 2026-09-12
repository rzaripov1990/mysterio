package proxy_test

import (
	"encoding/json"
	"strings"
	"testing"

	config "mysterio/configs"
	"mysterio/internal/masker"
	"mysterio/internal/proxy"
)

func graphqlTestMasker(t *testing.T) *masker.Masker {
	t.Helper()
	rules, err := config.LoadRules([]byte(`
graphql:
  json_keys:
    - name: iin
      keys: [iin]
      replace: "************"
    - name: email
      keys: [email]
      replace: "***"
`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := masker.New(config.Rules{JSONKeys: rules.GraphQL.JSONKeys}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMaskGraphQLResponseBody_MasksNestedDataKeys(t *testing.T) {
	body := []byte(`{"data":{"client":{"iin":"900101300123","email":"a@b.kz","name":"Bob"}}}`)
	out, changed, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(string(out), "900101300123") || strings.Contains(string(out), "a@b.kz") {
		t.Fatalf("sensitive value survived: %s", out)
	}
	if !strings.Contains(string(out), `"name":"Bob"`) {
		t.Fatalf("non-sensitive field lost: %s", out)
	}
}

func TestMaskGraphQLResponseBody_MasksInsideArrays(t *testing.T) {
	body := []byte(`{"data":{"clients":[{"iin":"900101300123"},{"iin":"900101300124"}]}}`)
	out, changed, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(string(out), "9001013001") {
		t.Fatalf("array element not masked: %s", out)
	}
}

func TestMaskGraphQLResponseBody_MasksErrorsExtensions(t *testing.T) {
	body := []byte(`{"data":null,"errors":[{"message":"denied","extensions":{"iin":"900101300123"}}]}`)
	out, changed, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(string(out), "900101300123") {
		t.Fatalf("errors.extensions not masked: %s", out)
	}
}

func TestMaskGraphQLResponseBody_NumericValueMasked(t *testing.T) {
	body := []byte(`{"data":{"client":{"iin":900101300123}}}`)
	out, _, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "900101300123") {
		t.Fatalf("numeric iin not masked: %s", out)
	}
}

func TestMaskGraphQLResponseBody_NoMatch_Unchanged(t *testing.T) {
	body := []byte(`{"data":{"ping":"pong"}}`)
	out, changed, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("expected changed=false")
	}
	if string(out) != string(body) {
		t.Fatalf("body altered: %s", out)
	}
}

func TestMaskGraphQLResponseBody_NonJSON_WrappedInEnvelope(t *testing.T) {
	body := []byte("<html><body>502 Bad Gateway</body></html>")
	out, changed, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 502)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true for non-JSON body")
	}
	var env struct {
		Data   any `json:"data"`
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				UpstreamStatus int    `json:"upstream_status"`
				Body           string `json:"body"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("envelope is not valid JSON: %v (%s)", err, out)
	}
	if env.Data != nil {
		t.Fatalf("expected data=null, got %v", env.Data)
	}
	if len(env.Errors) != 1 {
		t.Fatalf("expected one error, got %s", out)
	}
	if env.Errors[0].Extensions.UpstreamStatus != 502 {
		t.Fatalf("expected upstream_status 502, got %s", out)
	}
	if !strings.Contains(env.Errors[0].Extensions.Body, "502 Bad Gateway") {
		t.Fatalf("expected upstream body excerpt, got %s", out)
	}
}

func TestMaskGraphQLResponseBody_NonJSON_EnvelopeBodyIsMasked(t *testing.T) {
	body := []byte(`upstream error: {"iin":"900101300123"} not json`)
	out, _, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 500)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "900101300123") {
		t.Fatalf("envelope leaked sensitive upstream body: %s", out)
	}
}

func TestMaskGraphQLResponseBody_EmptyBody_WrappedInEnvelope(t *testing.T) {
	out, changed, err := proxy.MaskGraphQLResponseBody(nil, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true for empty body")
	}
	if !json.Valid(out) {
		t.Fatalf("envelope is not valid JSON: %s", out)
	}
}

func TestMaskGraphQLResponseBody_LongNonJSON_BodyExcerptTruncated(t *testing.T) {
	body := []byte(strings.Repeat("x", 10000))
	out, _, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)}, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 4096 {
		t.Fatalf("envelope not truncated: %d bytes", len(out))
	}
	if !json.Valid(out) {
		t.Fatalf("envelope is not valid JSON: %s", out)
	}
}

func TestMaskGraphQLResponseBody_MasksObjectValuedKey(t *testing.T) {
	rules, err := config.LoadRules([]byte(`
graphql:
  json_keys:
    - name: names
      keys: [fullName]
      replace: "***"
`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := masker.NewWithOptions(config.Rules{JSONKeys: rules.GraphQL.JSONKeys}, nil, masker.Options{MaskContainerValues: true})
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"data":{"client":{"fullName":{"ru":"Иванов Иван","kz":"Ivanov","en":"Ivanov"}}}}`)
	out, changed, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: m}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}
	if strings.Contains(string(out), "Иванов") {
		t.Fatalf("object-valued key not masked: %s", out)
	}
	if !strings.Contains(string(out), `"fullName":"***"`) {
		t.Fatalf("expected the whole object replaced, got: %s", out)
	}
}

func TestMaskGraphQLResponseBody_MasksArrayValuedKey(t *testing.T) {
	rules, err := config.LoadRules([]byte(`
graphql:
  json_keys:
    - name: phone
      keys: [phones]
      replace: "***"
`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := masker.NewWithOptions(config.Rules{JSONKeys: rules.GraphQL.JSONKeys}, nil, masker.Options{MaskContainerValues: true})
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"data":{"client":{"phones":["+77011234567","+77011234568"]}}}`)
	out, _, err := proxy.MaskGraphQLResponseBody(body, proxy.GraphQLMaskers{Doc: m}, 200)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "7701123456") {
		t.Fatalf("array-valued key not masked: %s", out)
	}
}

// A non-JSON upstream body is free text, not a GraphQL document: the graphql
// rules block has no regex mechanism, so the excerpt in the envelope is run
// through the global (log) rules as well. Without that, an ingress error page
// echoing a query string would leak verbatim.
func TestMaskGraphQLResponseBody_EnvelopeExcerptUsesGlobalTextRules(t *testing.T) {
	global, err := config.LoadRules([]byte(`
regex:
  - name: iin_bare
    pattern: '\b\d{12}\b'
    replace: "************"
  - name: form_password
    pattern: 'password=[^\\&"]*'
    replace: "password=***"
`))
	if err != nil {
		t.Fatal(err)
	}
	textMasker, err := masker.New(global, nil)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`<html>502 from ingress, iin=900101300123, password=hunter2</html>`)
	out, _, err := proxy.MaskGraphQLResponseBody(
		body,
		proxy.GraphQLMaskers{Doc: graphqlTestMasker(t), Text: textMasker},
		502,
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "900101300123") {
		t.Fatalf("envelope leaked the bare IIN: %s", out)
	}
	if strings.Contains(string(out), "hunter2") {
		t.Fatalf("envelope leaked the password: %s", out)
	}
}

func TestMaskGraphQLResponseBody_EnvelopeWithoutTextMasker(t *testing.T) {
	out, _, err := proxy.MaskGraphQLResponseBody(
		[]byte("plain text"),
		proxy.GraphQLMaskers{Doc: graphqlTestMasker(t)},
		500,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out) {
		t.Fatalf("expected valid JSON with a nil text masker, got %s", out)
	}
}
