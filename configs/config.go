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

	GraphQLEnabled bool
	GraphQLURL     string

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
	// GraphQL holds the rules applied to the /graphql route. They REPLACE the
	// global json_keys/regex there rather than extending them, so the block
	// must list every key that needs masking in GraphQL responses.
	GraphQL GraphQLRules `yaml:"graphql"`
}

type GraphQLRules struct {
	JSONKeys []JSONKeyRule `yaml:"json_keys"`
}

type JSONKeyRule struct {
	Name      string   `yaml:"name"`
	Keys      []string `yaml:"keys"`
	Replace   string   `yaml:"replace"`
	Normalize string   `yaml:"normalize"`

	// The fields below are graphql-block only (LoadRules rejects them in the
	// global json_keys). KeepFirst/KeepLast leave that many leading/trailing
	// characters (runes) of a string visible around Replace. ReplaceNumber is
	// the JSON literal written in place of a numeric value; empty means null.
	KeepFirst     int           `yaml:"keep_first"`
	KeepLast      int           `yaml:"keep_last"`
	ReplaceNumber NumberLiteral `yaml:"replace_number"`
}

// NumberLiteral is a JSON number literal taken verbatim from YAML, so the
// masked document gets exactly what the rule says (0, -1, 0.00). The zero
// value — replace_number omitted or null — stands for JSON null.
type NumberLiteral string

var jsonNumber = regexp.MustCompile(`^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$`)

func (n *NumberLiteral) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!null" {
		*n = ""
		return nil
	}
	tag := node.ShortTag()
	if node.Kind != yaml.ScalarNode || (tag != "!!int" && tag != "!!float") || !jsonNumber.MatchString(node.Value) {
		return fmt.Errorf("line %d: replace_number must be a JSON number or null, got %q", node.Line, node.Value)
	}
	*n = NumberLiteral(node.Value)
	return nil
}

// KeyPathSeparator splits a graphql json_keys entry into path segments
// (FIRSTNAME.RU). GraphQL field names cannot contain a dot, so it is never
// part of a key itself.
const KeyPathSeparator = "."

// KeyPathWildcard is a path segment matching any single key.
const KeyPathWildcard = "*"

// SplitKeyPath parses a graphql json_keys entry into its path segments.
func SplitKeyPath(key string) ([]string, error) {
	segs := strings.Split(key, KeyPathSeparator)
	literal := false
	for _, s := range segs {
		if s == "" {
			return nil, fmt.Errorf("key %q: empty path segment", key)
		}
		if s != KeyPathWildcard {
			literal = true
		}
	}
	if !literal {
		return nil, fmt.Errorf("key %q: path must name at least one key, not only %q", key, KeyPathWildcard)
	}
	return segs, nil
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

	cfg.GraphQLEnabled = getenvBool("GRAPHQL_ENABLED")
	if cfg.GraphQLEnabled {
		cfg.GraphQLURL = os.Getenv("GRAPHQL_URL")
		if cfg.GraphQLURL == "" {
			return Config{}, fmt.Errorf("GRAPHQL_ENABLED=true but GRAPHQL_URL is empty")
		}
		if _, err := url.Parse(cfg.GraphQLURL); err != nil {
			return Config{}, fmt.Errorf("GRAPHQL_URL: %w", err)
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

	if !cfg.LokiEnabled && !cfg.ElasticEnabled && !cfg.GraphQLEnabled {
		return Config{}, fmt.Errorf("at least one of LOKI_ENABLED, ELASTIC_ENABLED or GRAPHQL_ENABLED must be true")
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
	if cfg.GraphQLEnabled && len(rules.GraphQL.JSONKeys) == 0 {
		// The graphql block replaces the global rules on /graphql, so an empty
		// block (missing, or dropped by yaml because of wrong indentation)
		// would proxy every GraphQL response unmasked.
		return Config{}, fmt.Errorf("GRAPHQL_ENABLED=true but %q has no graphql.json_keys (check the block is top-level)", rulesPath)
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
	for _, k := range r.GraphQL.JSONKeys {
		if strings.Contains(k.Replace, "{hmac") {
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
		if err := validateGlobalJSONKey(k); err != nil {
			return Rules{}, err
		}
	}
	seen := make(map[string]string)
	for _, k := range rules.GraphQL.JSONKeys {
		if err := validateJSONKeyHMAC(k); err != nil {
			return Rules{}, fmt.Errorf("graphql: %w", err)
		}
		if err := validateGraphQLJSONKey(k, seen); err != nil {
			return Rules{}, fmt.Errorf("graphql: %w", err)
		}
	}
	return rules, nil
}

// validateGlobalJSONKey rejects graphql-only features in the log rules: they
// are also applied as regexes over embedded JSON text, where neither paths
// nor partial masks can be honoured — silently ignoring them would leak.
func validateGlobalJSONKey(r JSONKeyRule) error {
	if r.KeepFirst != 0 || r.KeepLast != 0 || r.ReplaceNumber != "" {
		return fmt.Errorf("json_keys %q: keep_first, keep_last and replace_number are only supported in the graphql block", r.Name)
	}
	for _, k := range r.Keys {
		if strings.Contains(k, KeyPathSeparator) {
			return fmt.Errorf("json_keys %q: key paths like %q are only supported in the graphql block", r.Name, k)
		}
	}
	return nil
}

// validateGraphQLJSONKey checks one graphql rule; seen maps every key path
// already declared to its rule name, so a path claimed twice is an error
// rather than an order-dependent override.
func validateGraphQLJSONKey(r JSONKeyRule, seen map[string]string) error {
	if r.KeepFirst < 0 || r.KeepLast < 0 {
		return fmt.Errorf("json_keys %q: keep_first and keep_last must not be negative", r.Name)
	}
	if (r.KeepFirst > 0 || r.KeepLast > 0) && strings.Contains(r.Replace, "{hmac") {
		return fmt.Errorf("json_keys %q: keep_first/keep_last cannot be combined with {hmac}", r.Name)
	}
	for _, k := range r.Keys {
		if _, err := SplitKeyPath(k); err != nil {
			return fmt.Errorf("json_keys %q: %w", r.Name, err)
		}
		if prev, dup := seen[k]; dup {
			return fmt.Errorf("json_keys %q: key %q is already declared in rule %q", r.Name, k, prev)
		}
		seen[k] = r.Name
	}
	return nil
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
