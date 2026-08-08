package masker

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	config "mystrio/configs"
)

type Masker struct {
	keyReplace map[string]string
	regex      []config.RegexRule
	// keyPatterns mask "key":"value" (and escaped \"key\":\"value\") in non-JSON text
	keyPatterns []keyPattern
}

type keyPattern struct {
	re      *regexp.Regexp
	replace string
}

func New(rules config.Rules) *Masker {
	m := &Masker{
		keyReplace: make(map[string]string),
		regex:      rules.Regex,
	}
	for _, r := range rules.JSONKeys {
		for _, k := range r.Keys {
			m.keyReplace[k] = r.Replace
			m.keyPatterns = append(m.keyPatterns, buildKeyPatterns(k, r.Replace)...)
		}
	}
	return m
}

func buildKeyPatterns(key, replace string) []keyPattern {
	quotedKey := regexp.QuoteMeta(key)
	return []keyPattern{
		// "biin":"890501402951"
		{
			re:      regexp.MustCompile(`"` + quotedKey + `"\s*:\s*"[^"]*"`),
			replace: fmt.Sprintf(`"%s":"%s"`, key, replace),
		},
		// "biin": 890501402951 (number)
		{
			re:      regexp.MustCompile(`"` + quotedKey + `"\s*:\s*-?\d+(?:\.\d+)?`),
			replace: fmt.Sprintf(`"%s":"%s"`, key, replace),
		},
		// \"biin\":\"890501402951\" (JSON embedded in a string / after remarshal)
		{
			re:      regexp.MustCompile(`\\"` + quotedKey + `\\"\s*:\s*\\"[^\\"]*\\"`),
			replace: fmt.Sprintf(`\"%s\":\"%s\"`, key, replace),
		},
	}
}

func (m *Masker) Apply(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return line
	}
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err == nil {
		m.walk(v)
		b, err := json.Marshal(v)
		if err != nil {
			return m.applyTextRules(line)
		}
		// Still run text rules in case of remaining escaped fragments
		return m.applyTextRules(string(b))
	}
	return m.applyTextRules(line)
}

// WalkAndMask recursively masks JSON keys in v (a decoded JSON value —
// map[string]any, []any, or scalar) in place, using the same json_keys
// rules as Apply. Unlike Apply, it does not run text/regex rules — callers
// pass already-decoded structured data, not a raw log line.
// Returns whether anything was changed.
func (m *Masker) WalkAndMask(v any) bool {
	before, _ := json.Marshal(v)
	m.walk(v)
	after, _ := json.Marshal(v)
	return string(before) != string(after)
}

func (m *Masker) applyTextRules(line string) string {
	out := line
	for _, kp := range m.keyPatterns {
		out = kp.re.ReplaceAllString(out, kp.replace)
	}
	for _, r := range m.regex {
		if re := r.Regexp(); re != nil {
			out = re.ReplaceAllString(out, r.Replace)
			// After outer JSON marshal, inner quotes are escaped: \"key\":\"value\"
			escPattern := escapeJSONRegex(r.Pattern)
			if escPattern != r.Pattern {
				if ere, err := regexp.Compile(escPattern); err == nil {
					out = ere.ReplaceAllString(out, escapeJSONReplace(r.Replace))
				}
			}
		}
	}
	return out
}

// escapeJSONRegex turns a pattern meant for "key":"val" into one matching \"key\":\"val\".
func escapeJSONRegex(pattern string) string {
	if !strings.Contains(pattern, `"`) {
		return pattern
	}
	return strings.ReplaceAll(pattern, `"`, `\\"`)
}

func escapeJSONReplace(replace string) string {
	return strings.ReplaceAll(replace, `"`, `\"`)
}

func (m *Masker) walk(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if repl, ok := m.keyReplace[k]; ok {
				switch val.(type) {
				case string, float64, bool, nil:
					t[k] = repl
					continue
				case json.Number:
					t[k] = repl
					continue
				}
			}
			if s, ok := val.(string); ok {
				if masked, changed := m.maskEmbeddedJSON(s); changed {
					t[k] = masked
					continue
				}
			}
			m.walk(val)
		}
	case []any:
		for i, el := range t {
			if s, ok := el.(string); ok {
				if masked, changed := m.maskEmbeddedJSON(s); changed {
					t[i] = masked
					continue
				}
			}
			m.walk(el)
		}
	}
}

// maskEmbeddedJSON masks JSON that is the whole string, or a suffix after prefix text
// (e.g. `https://host/path {"data":...}`).
func (m *Masker) maskEmbeddedJSON(s string) (string, bool) {
	if masked, ok := m.tryDecodeAndMask(s); ok {
		return masked, masked != s
	}
	idx := strings.IndexAny(s, "{[")
	if idx < 0 {
		return s, false
	}
	prefix := s[:idx]
	rest := s[idx:]
	masked, ok := m.tryDecodeAndMask(rest)
	if !ok {
		return s, false
	}
	return prefix + masked, true
}

func (m *Masker) tryDecodeAndMask(s string) (string, bool) {
	trim := strings.TrimSpace(s)
	if len(trim) < 2 || (trim[0] != '{' && trim[0] != '[') {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(trim))
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	m.walk(v)
	b, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	consumed := int(dec.InputOffset())
	if consumed < len(trim) {
		return string(b) + trim[consumed:], true
	}
	return string(b), true
}
