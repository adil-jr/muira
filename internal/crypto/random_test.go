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

func TestNewRecordID(t *testing.T) {
	a, b := NewRecordID(), NewRecordID()
	if len(a) != RecordIDSize || len(b) != RecordIDSize {
		t.Fatalf("record ID lengths %d and %d, want %d", len(a), len(b), RecordIDSize)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two record IDs are equal")
	}
	if bytes.Equal(a, make([]byte, RecordIDSize)) {
		t.Fatal("record ID is all zeros")
	}
}

func TestNewDEK(t *testing.T) {
	a, b := NewDEK(), NewDEK()
	if len(a) != KeySize || len(b) != KeySize {
		t.Fatalf("DEK lengths %d and %d, want %d", len(a), len(b), KeySize)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two DEKs are equal")
	}
	if bytes.Equal(a, make([]byte, KeySize)) {
		t.Fatal("DEK is all zeros")
	}
}
