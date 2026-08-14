package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
)

const hmacBytes = 8

var alreadyToken = regexp.MustCompile(`^~[A-Za-z0-9_-]{11}$`)

type Tokenizer struct{ key []byte }

func New(key []byte) *Tokenizer { return &Tokenizer{key: key} }

func IsToken(s string) bool { return alreadyToken.MatchString(s) }

func (t *Tokenizer) Token(raw, normalize string) string {
	if t == nil || len(t.key) == 0 {
		return ""
	}
	if IsToken(raw) {
		return raw
	}
	norm := applyNormalize(raw, normalize)
	if norm == "" {
		return ""
	}
	mac := hmac.New(sha256.New, t.key)
	_, _ = mac.Write([]byte(norm))
	sum := mac.Sum(nil)[:hmacBytes]
	return "~" + base64.RawURLEncoding.EncodeToString(sum)
}

func applyNormalize(raw, mode string) string {
	s := strings.TrimSpace(raw)
	switch mode {
	case "", "none":
		return s
	case "digits":
		var b strings.Builder
		for _, r := range s {
			if unicode.IsDigit(r) {
				b.WriteRune(r)
			}
		}
		return b.String()
	case "lower":
		return strings.ToLower(s)
	default:
		return s
	}
}
