package masker

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	config "mysterio/configs"
	"mysterio/internal/token"
)

var errNotObject = errors.New("graphql response is not a JSON object")

// GraphQL masks GraphQL response documents with the rules file's graphql
// block. Unlike the log masker it never changes the document's shape: keys
// keep their order and place, containers are descended into rather than
// replaced, and only string and number leaves are rewritten.
//
// A rule key is a dot-separated path matched against the end of a value's
// path (array indices are not part of the path): IIN, FIRSTNAME.RU,
// FIRSTNAME.*, Person.FIRSTNAME. A matched container hands its rule down to
// every leaf beneath it. When several rules match, the one anchored closest to
// the leaf wins, then the one with more literal segments, then more segments,
// then the one declared first.
type GraphQL struct {
	byLast   map[string][]*gqlPattern
	wildLast []*gqlPattern
	// text masks free text (a non-JSON upstream body) with the same rules
	// reduced to plain key names, and hosts the HMAC expansion.
	text *Masker
}

type gqlPattern struct {
	segs     []string
	literals int
	order    int
	rule     *gqlRule
}

type gqlRule struct {
	repl      replacement
	norm      string
	keepFirst int
	keepLast  int
	// number is the JSON literal for numeric leaves; empty writes null.
	number string
}

func NewGraphQL(rules []config.JSONKeyRule, tok *token.Tokenizer) (*GraphQL, error) {
	g := &GraphQL{byLast: make(map[string][]*gqlPattern)}
	textRules := make([]config.JSONKeyRule, 0, len(rules))
	order := 0
	for _, r := range rules {
		rule := &gqlRule{
			repl:      parseReplacement(r.Replace),
			norm:      r.Normalize,
			keepFirst: r.KeepFirst,
			keepLast:  r.KeepLast,
			number:    string(r.ReplaceNumber),
		}
		textRule := config.JSONKeyRule{Name: r.Name, Replace: r.Replace, Normalize: r.Normalize}
		for _, k := range r.Keys {
			segs, err := config.SplitKeyPath(k)
			if err != nil {
				return nil, fmt.Errorf("graphql rule %q: %w", r.Name, err)
			}
			p := &gqlPattern{segs: segs, order: order, rule: rule}
			order++
			for _, s := range segs {
				if s != config.KeyPathWildcard {
					p.literals++
				}
			}
			last := segs[len(segs)-1]
			if last == config.KeyPathWildcard {
				g.wildLast = append(g.wildLast, p)
			} else {
				g.byLast[last] = append(g.byLast[last], p)
			}
			textRule.Keys = append(textRule.Keys, lastLiteral(segs))
		}
		textRules = append(textRules, textRule)
	}
	text, err := New(config.Rules{JSONKeys: textRules}, tok)
	if err != nil {
		return nil, err
	}
	g.text = text
	return g, nil
}

// lastLiteral is the key a path is reduced to for free-text masking. It masks
// that key wherever it appears — stricter than the path, which is the safe
// direction for text that could not be parsed.
func lastLiteral(segs []string) string {
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != config.KeyPathWildcard {
			return segs[i]
		}
	}
	return segs[0]
}

// MaskDocument masks a GraphQL response. body must be a JSON object; the
// output is compact JSON in the original key order. When no value changes,
// the original body is returned untouched with changed=false.
func (g *GraphQL) MaskDocument(body []byte) ([]byte, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	first, err := dec.Token()
	if err != nil {
		return nil, false, err
	}
	if d, ok := first.(json.Delim); !ok || d != '{' {
		return nil, false, errNotObject
	}
	w := newDocWriter(g)
	if err := w.object(dec, nil, nil); err != nil {
		return nil, false, err
	}
	if !w.changed {
		return body, false, nil
	}
	return w.buf.Bytes(), true, nil
}

// ApplyText masks free text, such as a non-JSON upstream body, by plain key
// name in "key":"value" form.
func (g *GraphQL) ApplyText(s string) string {
	return g.text.Apply(s)
}

// match returns the best rule anchored exactly at path, or nil.
func (g *GraphQL) match(path []string) *gqlPattern {
	var best *gqlPattern
	consider := func(ps []*gqlPattern) {
		for _, p := range ps {
			if !p.matches(path) {
				continue
			}
			if best == nil || p.moreSpecificThan(best) {
				best = p
			}
		}
	}
	consider(g.byLast[path[len(path)-1]])
	consider(g.wildLast)
	return best
}

func (p *gqlPattern) matches(path []string) bool {
	if len(p.segs) > len(path) {
		return false
	}
	off := len(path) - len(p.segs)
	for i, s := range p.segs {
		if s != config.KeyPathWildcard && s != path[off+i] {
			return false
		}
	}
	return true
}

func (p *gqlPattern) moreSpecificThan(o *gqlPattern) bool {
	if p.literals != o.literals {
		return p.literals > o.literals
	}
	if len(p.segs) != len(o.segs) {
		return len(p.segs) > len(o.segs)
	}
	return p.order < o.order
}

func (g *GraphQL) maskString(r *gqlRule, s string) string {
	if r.keepFirst > 0 || r.keepLast > 0 {
		runes := []rune(s)
		if len(runes) <= r.keepFirst+r.keepLast {
			return r.repl.raw
		}
		return string(runes[:r.keepFirst]) + r.repl.raw + string(runes[len(runes)-r.keepLast:])
	}
	return g.text.replaceScalar(s, keyRule{repl: r.repl, norm: r.norm})
}

// maskEmbedded masks JSON carried inside a string that no rule governs — the
// whole string, or a suffix after prefix text ("bad input {...}"). The
// embedded document is matched from its own root.
func (g *GraphQL) maskEmbedded(s string) (string, bool) {
	if out, ok := g.tryEmbedded(s); ok {
		return out, true
	}
	idx := strings.IndexAny(s, "{[")
	if idx <= 0 {
		return s, false
	}
	if out, ok := g.tryEmbedded(s[idx:]); ok {
		return s[:idx] + out, true
	}
	return s, false
}

func (g *GraphQL) tryEmbedded(s string) (string, bool) {
	trim := strings.TrimSpace(s)
	if len(trim) < 2 || (trim[0] != '{' && trim[0] != '[') {
		return "", false
	}
	dec := json.NewDecoder(strings.NewReader(trim))
	dec.UseNumber()
	w := newDocWriter(g)
	if err := w.value(dec, nil, nil); err != nil || !w.changed {
		return "", false
	}
	return w.buf.String() + trim[dec.InputOffset():], true
}

// docWriter re-emits a token stream as compact JSON, masking leaves on the way.
type docWriter struct {
	g       *GraphQL
	buf     bytes.Buffer
	enc     *json.Encoder
	changed bool
}

func newDocWriter(g *GraphQL) *docWriter {
	w := &docWriter{g: g}
	w.enc = json.NewEncoder(&w.buf)
	w.enc.SetEscapeHTML(false)
	return w
}

func (w *docWriter) value(dec *json.Decoder, path []string, gov *gqlRule) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return w.object(dec, path, gov)
		case '[':
			return w.array(dec, path, gov)
		}
		return fmt.Errorf("unexpected delimiter %q", t)
	case string:
		out := t
		if gov != nil {
			out = w.g.maskString(gov, t)
		} else if masked, ok := w.g.maskEmbedded(t); ok {
			out = masked
		}
		w.changed = w.changed || out != t
		return w.writeString(out)
	case json.Number:
		if gov == nil {
			w.buf.WriteString(t.String())
			return nil
		}
		lit := gov.number
		if lit == "" {
			lit = "null"
		}
		w.changed = w.changed || lit != t.String()
		w.buf.WriteString(lit)
		return nil
	case bool:
		if t {
			w.buf.WriteString("true")
		} else {
			w.buf.WriteString("false")
		}
		return nil
	case nil:
		w.buf.WriteString("null")
		return nil
	}
	return fmt.Errorf("unexpected token %T", tok)
}

// object is called after the opening '{' has been read.
func (w *docWriter) object(dec *json.Decoder, path []string, gov *gqlRule) error {
	w.buf.WriteByte('{')
	for i := 0; dec.More(); i++ {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("unexpected object key %T", tok)
		}
		if i > 0 {
			w.buf.WriteByte(',')
		}
		if err := w.writeString(key); err != nil {
			return err
		}
		w.buf.WriteByte(':')
		child := append(path, key)
		childGov := gov
		if p := w.g.match(child); p != nil {
			childGov = p.rule
		}
		if err := w.value(dec, child, childGov); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	w.buf.WriteByte('}')
	return nil
}

// array is called after the opening '[' has been read. Elements share the
// array's path: indices are not path segments.
func (w *docWriter) array(dec *json.Decoder, path []string, gov *gqlRule) error {
	w.buf.WriteByte('[')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			w.buf.WriteByte(',')
		}
		if err := w.value(dec, path, gov); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	w.buf.WriteByte(']')
	return nil
}

func (w *docWriter) writeString(s string) error {
	if err := w.enc.Encode(s); err != nil {
		return err
	}
	w.buf.Truncate(w.buf.Len() - 1) // Encode appends a newline
	return nil
}
