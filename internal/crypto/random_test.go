package crypto

import (
	"bytes"
	"testing"
)

func TestNewSalt(t *testing.T) {
	a, b := NewSalt(), NewSalt()
	if len(a) != SaltSize || len(b) != SaltSize {
		t.Fatalf("salt lengths %d and %d, want %d", len(a), len(b), SaltSize)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two salts are equal")
	}
	if bytes.Equal(a, make([]byte, SaltSize)) {
		t.Fatal("salt is all zeros")
	}
}
