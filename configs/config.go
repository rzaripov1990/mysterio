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
	// ElasticMessageField is Grafana's "Message field name" for Elasticsearch
	// logs. Empty (default) means the whole _source document is the message;
	// set to e.g. "log" when the datasource Message field name is "log".
	ElasticMessageField string

	TestMeEnabled bool
	BasePath      string

	RulesPath    string
	RawRulesYAML []byte
	MaskHMACKey  []byte
}

const minHMACKeyBytes = 32

var hmacPlaceholder = regexp.MustCompile(`\{hmac(?::\$(\d+))?\}`)

type Rules struct {
	JSONKeys []JSONKeyRule `yaml:"json_keys"`
	Regex    []RegexRule   `yaml:"regex"`
}

type JSONKeyRule struct {
	Name      string   `yaml:"name"`
	Keys      []string `yaml:"keys"`
	Replace   string   `yaml:"replace"`
	Normalize string   `yaml:"normalize"`
}

type RegexRule struct {
	Name      string `yaml:"name"`
	Pattern   string `yaml:"pattern"`
	Replace   string `yaml:"replace"`
	Normalize string `yaml:"normalize"`
	re        *regexp.Regexp
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
		cfg.ElasticMessageField = os.Getenv("ELASTIC_MESSAGE_FIELD")
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
	if RulesUseHMAC(rules) {
		key := os.Getenv("MASK_HMAC_KEY")
		if len(key) < minHMACKeyBytes {
			return Config{}, fmt.Errorf("MASK_HMAC_KEY is required (min %d bytes) because rules use {hmac}", minHMACKeyBytes)
		}
		cfg.MaskHMACKey = []byte(key)
	}
	return cfg, nil
}

func RulesUseHMAC(r Rules) bool {
	for _, k := range r.JSONKeys {
		if strings.Contains(k.Replace, "{hmac") {
			return true
		}
	}
	for _, x := range r.Regex {
		if strings.Contains(x.Replace, "{hmac") {
			return true
		}
	}
	return false
}

func validateNormalize(name, v string) error {
	switch v {
	case "", "none", "digits", "lower":
		return nil
	default:
		return fmt.Errorf("rule %q: unknown normalize %q (want none, digits, or lower)", name, v)
	}
}

func hmacSlots(replace string) ([]hmacSlot, error) {
	matches := hmacPlaceholder.FindAllStringSubmatchIndex(replace, -1)
	covered := make([]bool, len(replace))
	var slots []hmacSlot
	for _, m := range matches {
		for i := m[0]; i < m[1]; i++ {
			covered[i] = true
		}
		slot := hmacSlot{}
		if m[2] >= 0 {
			n, err := strconv.Atoi(replace[m[2]:m[3]])
			if err != nil {
				return nil, fmt.Errorf("malformed {hmac} placeholder in %q", replace)
			}
			slot.Group = n
			slot.HasGroup = true
		}
		slots = append(slots, slot)
	}
	if idx := indexUncoveredHMAC(replace, covered); idx >= 0 {
		return nil, fmt.Errorf("malformed {hmac} placeholder in %q", replace)
	}
	return slots, nil
}

func indexUncoveredHMAC(replace string, covered []bool) int {
	for i := 0; i < len(replace); {
		j := strings.Index(replace[i:], "{hmac")
		if j < 0 {
			return -1
		}
		pos := i + j
		if pos >= len(covered) || !covered[pos] {
			return pos
		}
		i = pos + 1
	}
	return -1
}

type hmacSlot struct {
	Group    int
	HasGroup bool
}

func validateJSONKeyHMAC(r JSONKeyRule) error {
	if err := validateNormalize(r.Name, r.Normalize); err != nil {
		return err
	}
	slots, err := hmacSlots(r.Replace)
	if err != nil {
		return fmt.Errorf("json_keys %q: %w", r.Name, err)
	}
	for _, s := range slots {
		if s.HasGroup {
			return fmt.Errorf("json_keys %q: {hmac:$N} is not allowed (the whole scalar is hashed)", r.Name)
		}
	}
	return nil
}

func validateRegexHMAC(r RegexRule) error {
	if err := validateNormalize(r.Name, r.Normalize); err != nil {
		return err
	}
	slots, err := hmacSlots(r.Replace)
	if err != nil {
		return fmt.Errorf("regex %q: %w", r.Name, err)
	}
	n := 0
	if r.re != nil {
		n = r.re.NumSubexp()
	}
	for _, s := range slots {
		if !s.HasGroup {
			continue
		}
		if s.Group < 1 || s.Group > n {
			return fmt.Errorf("regex %q: {hmac:$%d} but pattern has %d capture groups", r.Name, s.Group, n)
		}
	}
	return nil
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
		if err := validateRegexHMAC(rules.Regex[i]); err != nil {
			return Rules{}, err
		}
	}
	for _, k := range rules.JSONKeys {
		if err := validateJSONKeyHMAC(k); err != nil {
			return Rules{}, err
		}
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
