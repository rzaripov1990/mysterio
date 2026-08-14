package masker

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	config "mysterio/configs"
	"mysterio/internal/token"
)

var (
	hmacPlaceholder = regexp.MustCompile(`\{hmac(?::\$(\d+))?\}`)
	allStars        = regexp.MustCompile(`^\*+$`)
)

type Masker struct {
	tok         *token.Tokenizer
	keyReplace  map[string]keyRule
	regex       []compiledRegex
	keyPatterns []keyPattern
}

type keyRule struct {
	repl replacement
	norm string
}

type keyPattern struct {
	re     *regexp.Regexp
	static string
	hmac   bool
	repl   replacement
	norm   string
	wrap   func(string) string
}

type compiledRegex struct {
	re      *regexp.Regexp
	repl    replacement
	norm    string
	escRe   *regexp.Regexp
	escRepl replacement
}

type replacement struct {
	raw   string
	parts []replPart
	hmac  bool
}

type replPart struct {
	lit   string
	hmac  bool
	group int
}

func New(rules config.Rules, tok *token.Tokenizer) (*Masker, error) {
	if config.RulesUseHMAC(rules) && tok == nil {
		return nil, fmt.Errorf("MASK_HMAC_KEY is not set but rules use {hmac}")
	}
	m := &Masker{
		tok:        tok,
		keyReplace: make(map[string]keyRule),
	}
	for _, r := range rules.JSONKeys {
		repl := parseReplacement(r.Replace)
		rule := keyRule{repl: repl, norm: r.Normalize}
		for _, k := range r.Keys {
			m.keyReplace[k] = rule
			m.keyPatterns = append(m.keyPatterns, buildKeyPatterns(k, repl, r.Normalize)...)
		}
	}
	for _, r := range rules.Regex {
		cr := compiledRegex{
			re:   r.Regexp(),
			repl: parseReplacement(r.Replace),
			norm: r.Normalize,
		}
		escPattern := escapeJSONRegex(r.Pattern)
		if escPattern != r.Pattern {
			if ere, err := regexp.Compile(escPattern); err == nil {
				cr.escRe = ere
				cr.escRepl = parseReplacement(escapeJSONReplace(r.Replace))
			}
		}
		m.regex = append(m.regex, cr)
	}
	return m, nil
}

func parseReplacement(s string) replacement {
	matches := hmacPlaceholder.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return replacement{raw: s}
	}
	var parts []replPart
	last := 0
	for _, m := range matches {
		if m[0] > last {
			parts = append(parts, replPart{lit: s[last:m[0]]})
		}
		p := replPart{hmac: true}
		if m[2] >= 0 {
			p.group, _ = strconv.Atoi(s[m[2]:m[3]])
		}
		parts = append(parts, p)
		last = m[1]
	}
	if last < len(s) {
		parts = append(parts, replPart{lit: s[last:]})
	}
	return replacement{raw: s, parts: parts, hmac: true}
}

func buildKeyPatterns(key string, repl replacement, norm string) []keyPattern {
	quotedKey := regexp.QuoteMeta(key)
	if !repl.hmac {
		return []keyPattern{
			{
				re:     regexp.MustCompile(`"` + quotedKey + `"\s*:\s*"[^"]*"`),
				static: fmt.Sprintf(`"%s":"%s"`, key, repl.raw),
			},
			{
				re:     regexp.MustCompile(`"` + quotedKey + `"\s*:\s*-?\d+(?:\.\d+)?`),
				static: fmt.Sprintf(`"%s":"%s"`, key, repl.raw),
			},
			{
				re:     regexp.MustCompile(`\\"` + quotedKey + `\\"\s*:\s*\\"[^\\"]*\\"`),
				static: fmt.Sprintf(`\"%s\":\"%s\"`, key, repl.raw),
			},
		}
	}
	wrap := func(tok string) string { return fmt.Sprintf(`"%s":"%s"`, key, tok) }
	wrapEsc := func(tok string) string { return fmt.Sprintf(`\"%s\":\"%s\"`, key, tok) }
	return []keyPattern{
		{
			re:   regexp.MustCompile(`"` + quotedKey + `"\s*:\s*"([^"]*)"`),
			hmac: true, repl: repl, norm: norm, wrap: wrap,
		},
		{
			re:   regexp.MustCompile(`"` + quotedKey + `"\s*:\s*(-?\d+(?:\.\d+)?)`),
			hmac: true, repl: repl, norm: norm, wrap: wrap,
		},
		{
			re:   regexp.MustCompile(`\\"` + quotedKey + `\\"\s*:\s*\\"([^\\"]*)\\"`),
			hmac: true, repl: repl, norm: norm, wrap: wrapEsc,
		},
	}
}

func (m *Masker) Apply(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return line
	}
	v, ok := decodeJSONValue(trimmed)
	if !ok {
		return m.applyTextRules(line)
	}
	m.walk(v)
	b, err := json.Marshal(v)
	if err != nil {
		return m.applyTextRules(line)
	}
	return m.applyTextRules(string(b))
}

func decodeJSONValue(s string) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	rest := strings.TrimSpace(s[int(dec.InputOffset()):])
	if rest != "" {
		return nil, false
	}
	return v, true
}

// WalkAndMask recursively masks a decoded JSON value in place using json_keys
// (by name) and maskEmbeddedJSON for string values that contain JSON. It does
// not run full Apply/regex on every string — callers that need log-line regex
// (Elasticsearch message field) use Apply / ApplyStrings separately.
// Returns whether anything was changed.
func (m *Masker) WalkAndMask(v any) bool {
	before, _ := json.Marshal(v)
	m.walk(v)
	after, _ := json.Marshal(v)
	return string(before) != string(after)
}

// ApplyStrings runs Apply on every string leaf in v (map/array), in place.
// Used when Elasticsearch message field is empty (whole _source is the message).
func (m *Masker) ApplyStrings(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok {
				masked := m.Apply(s)
				if masked != s {
					t[k] = masked
					changed = true
				}
				continue
			}
			if m.ApplyStrings(val) {
				changed = true
			}
		}
	case []any:
		for i, el := range t {
			if s, ok := el.(string); ok {
				masked := m.Apply(s)
				if masked != s {
					t[i] = masked
					changed = true
				}
				continue
			}
			if m.ApplyStrings(el) {
				changed = true
			}
		}
	}
	return changed
}

func (m *Masker) applyTextRules(line string) string {
	out := line
	for _, kp := range m.keyPatterns {
		if kp.hmac {
			out = kp.re.ReplaceAllStringFunc(out, func(match string) string {
				sub := kp.re.FindStringSubmatch(match)
				raw := ""
				if len(sub) > 1 {
					raw = sub[1]
				}
				return kp.wrap(m.hashOrSkip(raw, kp.norm))
			})
			continue
		}
		out = kp.re.ReplaceAllString(out, kp.static)
	}
	for _, r := range m.regex {
		out = m.applyRegex(out, r.re, r.repl, r.norm)
		if r.escRe != nil {
			out = m.applyRegex(out, r.escRe, r.escRepl, r.norm)
		}
	}
	return out
}

func (m *Masker) applyRegex(src string, re *regexp.Regexp, repl replacement, norm string) string {
	if re == nil {
		return src
	}
	if !repl.hmac {
		return re.ReplaceAllString(src, repl.raw)
	}
	return re.ReplaceAllStringFunc(src, func(match string) string {
		sub := re.FindStringSubmatch(match)
		idx := re.FindStringSubmatchIndex(match)
		return m.expand(repl, match, sub, idx, re, norm)
	})
}

func (m *Masker) expand(repl replacement, match string, sub []string, idx []int, re *regexp.Regexp, norm string) string {
	var b strings.Builder
	for _, p := range repl.parts {
		if p.hmac {
			raw := match
			if p.group > 0 && p.group < len(sub) {
				raw = sub[p.group]
			}
			b.WriteString(m.hashOrSkip(raw, norm))
			continue
		}
		if re != nil && idx != nil {
			b.WriteString(string(re.ExpandString(nil, p.lit, match, idx)))
			continue
		}
		b.WriteString(p.lit)
	}
	return b.String()
}

func (m *Masker) hashOrSkip(raw, norm string) string {
	if raw == "" || allStars.MatchString(raw) {
		return "***"
	}
	if token.IsToken(raw) {
		return raw
	}
	if m.tok == nil {
		return "***"
	}
	out := m.tok.Token(raw, norm)
	if out == "" {
		return "***"
	}
	return out
}

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
			if rule, ok := m.keyReplace[k]; ok {
				switch val := val.(type) {
				case string:
					t[k] = m.replaceScalar(val, rule)
					continue
				case json.Number:
					t[k] = m.replaceScalar(val.String(), rule)
					continue
				case float64:
					t[k] = m.replaceScalar(strconv.FormatFloat(val, 'f', -1, 64), rule)
					continue
				case bool, nil:
					if rule.repl.hmac {
						t[k] = "***"
					} else {
						t[k] = rule.repl.raw
					}
					continue
				}
			}
			if s, ok := val.(string); ok {
				if masked, ch := m.maskEmbeddedJSON(s); ch {
					t[k] = masked
				}
				continue
			}
			m.walk(val)
		}
	case []any:
		for i, el := range t {
			if s, ok := el.(string); ok {
				if masked, ch := m.maskEmbeddedJSON(s); ch {
					t[i] = masked
				}
				continue
			}
			m.walk(el)
		}
	}
}

func (m *Masker) replaceScalar(raw string, rule keyRule) string {
	if !rule.repl.hmac {
		return rule.repl.raw
	}
	return m.expand(rule.repl, raw, []string{raw}, nil, nil, rule.norm)
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
	dec.UseNumber()
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
