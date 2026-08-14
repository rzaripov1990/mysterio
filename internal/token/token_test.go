package token_test

import (
	"testing"

	"mysterio/internal/token"
)

const testKey = "0123456789abcdef0123456789abcdef"

func TestToken_KnownVector(t *testing.T) {
	tok := token.New([]byte(testKey))
	got := tok.Token("890501402951", "digits")
	if got != "~nAqddoqkCK8" {
		t.Fatalf("got %q", got)
	}
}

func TestToken_DigitsPhone(t *testing.T) {
	tok := token.New([]byte(testKey))
	a := tok.Token("+77012345678", "digits")
	b := tok.Token("77012345678", "digits")
	if a != "~m0QzM6clTq0" || a != b {
		t.Fatalf("a=%q b=%q", a, b)
	}
}

func TestToken_Lower(t *testing.T) {
	tok := token.New([]byte(testKey))
	if tok.Token("Foo", "lower") != tok.Token("foo", "lower") {
		t.Fatal("lower normalize must collide")
	}
}

func TestToken_AlreadyToken_NotRehashed(t *testing.T) {
	tok := token.New([]byte(testKey))
	existing := "~nAqddoqkCK8" // contains digits
	if got := tok.Token(existing, "digits"); got != existing {
		t.Fatalf("rehashed: %q", got)
	}
}

func TestIsToken(t *testing.T) {
	if !token.IsToken("~nAqddoqkCK8") {
		t.Fatal("expected token")
	}
	if token.IsToken("890501402951") || token.IsToken("***") {
		t.Fatal("false positive")
	}
}
