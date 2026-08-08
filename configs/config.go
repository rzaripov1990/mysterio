package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr       string
	MaxResponseBytes int64
	Rules            Rules

	LokiEnabled bool
	LokiURL     string

	ElasticEnabled bool
	ElasticURL     string

	TestMeEnabled bool
	BasePath      string

	RulesPath    string
	RawRulesYAML []byte
}

type Rules struct {
	JSONKeys []JSONKeyRule `yaml:"json_keys"`
	Regex    []RegexRule   `yaml:"regex"`
}

type JSONKeyRule struct {
	Name    string   `yaml:"name"`
	Keys    []string `yaml:"keys"`
	Replace string   `yaml:"replace"`
}

type RegexRule struct {
	Name    string `yaml:"name"`
	Pattern string `yaml:"pattern"`
	Replace string `yaml:"replace"`
	re      *regexp.Regexp
}

func (r RegexRule) Regexp() *regexp.Regexp { return r.re }

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:       getenv("PORT", ":8080"),
		MaxResponseBytes: 32 << 20,
	}

	if v := os.Getenv("MAX_RESPONSE_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return Config{}, fmt.Errorf("MAX_RESPONSE_BYTES: invalid value %q", v)
		}
		cfg.MaxResponseBytes = n
	}

	cfg.LokiEnabled = getenvBool("LOKI_ENABLED")
	if cfg.LokiEnabled {
		cfg.LokiURL = os.Getenv("LOKI_URL")
		if cfg.LokiURL == "" {
			return Config{}, fmt.Errorf("LOKI_ENABLED=true but LOKI_URL is empty")
		}
		if _, err := url.Parse(cfg.LokiURL); err != nil {
			return Config{}, fmt.Errorf("LOKI_URL: %w", err)
		}
	}

	cfg.ElasticEnabled = getenvBool("ELASTIC_ENABLED")
	if cfg.ElasticEnabled {
		cfg.ElasticURL = os.Getenv("ELASTIC_URL")
		if cfg.ElasticURL == "" {
			return Config{}, fmt.Errorf("ELASTIC_ENABLED=true but ELASTIC_URL is empty")
		}
		if _, err := url.Parse(cfg.ElasticURL); err != nil {
			return Config{}, fmt.Errorf("ELASTIC_URL: %w", err)
		}
	}

	cfg.TestMeEnabled = getenvBool("TEST_ME_ENABLED")

	cfg.BasePath = os.Getenv("BASE_PATH")
	if cfg.BasePath != "" {
		if !strings.HasPrefix(cfg.BasePath, "/") {
			return Config{}, fmt.Errorf("BASE_PATH must start with '/', got %q", cfg.BasePath)
		}
		if strings.HasSuffix(cfg.BasePath, "/") {
			return Config{}, fmt.Errorf("BASE_PATH must not end with '/', got %q", cfg.BasePath)
		}
	}

	if !cfg.LokiEnabled && !cfg.ElasticEnabled {
		return Config{}, fmt.Errorf("at least one of LOKI_ENABLED or ELASTIC_ENABLED must be true")
	}

	rulesPath := os.Getenv("RULES_PATH")
	if rulesPath == "" {
		return Config{}, fmt.Errorf("RULES_PATH is required")
	}
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return Config{}, fmt.Errorf("read RULES_PATH %q: %w", rulesPath, err)
	}
	rules, err := LoadRules(data)
	if err != nil {
		return Config{}, err
	}
	cfg.RulesPath = rulesPath
	cfg.RawRulesYAML = data
	cfg.Rules = rules
	return cfg, nil
}

func LoadRules(data []byte) (Rules, error) {
	var rules Rules
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return Rules{}, fmt.Errorf("parse rules: %w", err)
	}
	for i := range rules.Regex {
		re, err := regexp.Compile(rules.Regex[i].Pattern)
		if err != nil {
			return Rules{}, fmt.Errorf("regex %q: %w", rules.Regex[i].Name, err)
		}
		rules.Regex[i].re = re
	}
	return rules, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func getenvBool(k string) bool {
	v, ok := os.LookupEnv(k)
	if !ok || v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}
