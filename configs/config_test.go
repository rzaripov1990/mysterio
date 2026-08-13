package config_test

import (
	"os"
	"path/filepath"
	"testing"

	config "mysterio/configs"
)

func TestLoadRules_JSONKeysAndRegex(t *testing.T) {
	content := `
json_keys:
  - name: iin
    keys: [iin, biin]
    replace: "************"
regex:
  - name: email
    pattern: 'foo@bar\.com'
    replace: "***@***"
`
	rules, err := config.LoadRules([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.JSONKeys) != 1 || len(rules.JSONKeys[0].Keys) != 2 {
		t.Fatalf("unexpected json_keys: %+v", rules.JSONKeys)
	}
	if len(rules.Regex) != 1 || rules.Regex[0].Replace != "***@***" {
		t.Fatalf("unexpected regex: %+v", rules.Regex)
	}
	if rules.Regex[0].Regexp() == nil {
		t.Fatal("expected compiled regexp")
	}
}

func TestLoadRules_InvalidRegex(t *testing.T) {
	content := `
regex:
  - name: bad
    pattern: "("
    replace: "x"
`
	if _, err := config.LoadRules([]byte(content)); err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

const validRulesYAML = `
json_keys:
  - name: iin
    keys: [iin]
    replace: "************"
`

func writeRulesFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func clearBackendEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"LOKI_ENABLED", "LOKI_URL",
		"ELASTIC_ENABLED", "ELASTIC_URL", "ELASTIC_MESSAGE_FIELD",
		"MAX_RESPONSE_BYTES",
		"TEST_ME_ENABLED", "BASE_PATH",
		"RULES_PATH",
	} {
		t.Setenv(k, "")
	}
}

func TestLoad_NoBackendEnabled_Error(t *testing.T) {
	clearBackendEnv(t)
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when neither backend is enabled")
	}
}

func TestLoad_LokiEnabledMissingURL_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for LOKI_ENABLED=true with empty LOKI_URL")
	}
}

func TestLoad_LokiEnabledInvalidURL_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://example.com/%zz")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for unparseable LOKI_URL")
	}
}

func TestLoad_LokiEnabledOnly_Success(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LokiEnabled || cfg.LokiURL != "http://loki:3100" {
		t.Fatalf("unexpected loki config: %+v", cfg)
	}
	if cfg.ElasticEnabled {
		t.Fatal("expected ElasticEnabled=false")
	}
}

func TestLoad_ElasticEnabledMissingURL_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("ELASTIC_ENABLED", "true")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for ELASTIC_ENABLED=true with empty ELASTIC_URL")
	}
}

func TestLoad_BothEnabled_Success(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("ELASTIC_ENABLED", "true")
	t.Setenv("ELASTIC_URL", "http://elastic:9200")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LokiEnabled || !cfg.ElasticEnabled {
		t.Fatalf("expected both backends enabled: %+v", cfg)
	}
	if cfg.ElasticURL != "http://elastic:9200" {
		t.Fatalf("unexpected elastic url: %+v", cfg)
	}
	if cfg.ElasticMessageField != "" {
		t.Fatalf("expected empty ElasticMessageField by default, got %q", cfg.ElasticMessageField)
	}
}

func TestLoad_ElasticMessageField(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("ELASTIC_ENABLED", "true")
	t.Setenv("ELASTIC_URL", "http://elastic:9200")
	t.Setenv("ELASTIC_MESSAGE_FIELD", "log")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ElasticMessageField != "log" {
		t.Fatalf("ElasticMessageField=%q want log", cfg.ElasticMessageField)
	}
}

func TestLoad_TestMeEnabled_DefaultFalse(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TestMeEnabled {
		t.Fatal("expected TestMeEnabled=false by default")
	}
	if cfg.BasePath != "" {
		t.Fatalf("expected empty BasePath by default, got %q", cfg.BasePath)
	}
}

func TestLoad_TestMeEnabled_True(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("TEST_ME_ENABLED", "true")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TestMeEnabled {
		t.Fatal("expected TestMeEnabled=true")
	}
}

func TestLoad_BasePath_Valid(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("BASE_PATH", "/mysterio")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BasePath != "/mysterio" {
		t.Fatalf("unexpected BasePath: %q", cfg.BasePath)
	}
}

func TestLoad_BasePath_MissingLeadingSlash_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("BASE_PATH", "mysterio")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for BASE_PATH without leading '/'")
	}
}

func TestLoad_BasePath_TrailingSlash_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("BASE_PATH", "/mysterio/")
	t.Setenv("RULES_PATH", writeRulesFile(t, validRulesYAML))
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for BASE_PATH with trailing '/'")
	}
}

func TestLoad_RulesPathMissing_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when RULES_PATH is unset")
	}
}

func TestLoad_RulesPathNonexistentFile_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("RULES_PATH", filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when RULES_PATH file does not exist")
	}
}

func TestLoad_RulesPathInvalidYAML_Error(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	t.Setenv("RULES_PATH", writeRulesFile(t, "regex:\n  - name: bad\n    pattern: \"(\"\n    replace: x\n"))
	if _, err := config.Load(); err == nil {
		t.Fatal("expected error for RULES_PATH file containing invalid regex")
	}
}

func TestLoad_RulesPathValid_PopulatesConfig(t *testing.T) {
	clearBackendEnv(t)
	t.Setenv("LOKI_ENABLED", "true")
	t.Setenv("LOKI_URL", "http://loki:3100")
	path := writeRulesFile(t, validRulesYAML)
	t.Setenv("RULES_PATH", path)

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RulesPath != path {
		t.Fatalf("unexpected RulesPath: %q", cfg.RulesPath)
	}
	if string(cfg.RawRulesYAML) != validRulesYAML {
		t.Fatalf("RawRulesYAML does not match file content: %q", cfg.RawRulesYAML)
	}
	if len(cfg.Rules.JSONKeys) != 1 || cfg.Rules.JSONKeys[0].Name != "iin" {
		t.Fatalf("unexpected parsed rules: %+v", cfg.Rules)
	}
}
