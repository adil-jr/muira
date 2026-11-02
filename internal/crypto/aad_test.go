package crypto

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// fieldsOf turns strings into AAD fields.
func fieldsOf(ss ...string) [][]byte {
	fs := make([][]byte, len(ss))
	for i, s := range ss {
		fs[i] = []byte(s)
	}
	return fs
}

func mustEncodeAAD(t *testing.T, fields ...[]byte) []byte {
	t.Helper()
	b, err := encodeAAD(fields...)
	if err != nil {
		t.Fatalf("encodeAAD: %v", err)
	}
	return b
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestEncodeAADBytes checks the exact encoding against bytes written by hand
// from ADR 0002 (the format is ours, so these are not derived from running
// our code). It catches little-endian or 64-bit prefixes.
func TestEncodeAADBytes(t *testing.T) {
	long := bytes.Repeat([]byte{'z'}, 300) // length 0x012c uses two prefix bytes
	tests := []struct {
		name   string
		fields [][]byte
		want   string
	}{
		{"no fields", nil, ""},
		{"one empty field", fieldsOf(""), "00 00 00 00"},
		{"short and empty", fieldsOf("ab", ""), "00 00 00 02 61 62 00 00 00 00"},
		{"empty and short", fieldsOf("", "c"), "00 00 00 00 00 00 00 01 63"},
		{"300-byte field", [][]byte{long}, "00 00 01 2c" + strings.Repeat(" 7a", 300)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mustEncodeAAD(t, tc.fields...)
			if want := mustHex(t, tc.want); !bytes.Equal(got, want) {
				t.Fatalf("got %x, want %x", got, want)
			}
		})
	}
}

// TestRecordAADBytes checks the complete record AAD for a fixed ID, written
// by hand from ADR 0002: label, version 0x01 and ID, each with a uint32
// big-endian length prefix.
func TestRecordAADBytes(t *testing.T) {
	id := mustHex(t, "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")
	want := mustHex(t, ""+
		"00 00 00 0c 6d 75 69 72 61 2f 72 65 63 6f 72 64"+ // "muira/record"
		"00 00 00 01 01"+ // version 0x01
		"00 00 00 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f") // record ID
	got, err := recordAAD(id)
	if err != nil {
		t.Fatalf("recordAAD: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x\nwant %x", got, want)
	}
}

// TestEncodeAADDistinct covers the classic ambiguities of plain
// concatenation.
func TestEncodeAADDistinct(t *testing.T) {
	pairs := [][2][][]byte{
		{fieldsOf("ab", "c"), fieldsOf("a", "bc")},
		{fieldsOf(), fieldsOf("")},
		{fieldsOf("", ""), fieldsOf("")},
	}
	for _, p := range pairs {
		if bytes.Equal(mustEncodeAAD(t, p[0]...), mustEncodeAAD(t, p[1]...)) {
			t.Errorf("%q and %q encode to the same bytes", p[0], p[1])
		}
	}
}

// decodeAAD is a test-only decoder for encodeAAD. If every encoding decodes
// back to its own field list, the encoding is injective.
func decodeAAD(b []byte) ([][]byte, bool) {
	var fields [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, false
		}
		n := uint64(binary.BigEndian.Uint32(b))
		b = b[4:]
		if uint64(len(b)) < n {
			return nil, false
		}
		fields = append(fields, b[:n])
		b = b[n:]
	}
	return fields, true
}

func sameFields(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// TestEncodeAADInjective encodes every list of up to 3 fields over a small
// alphabet (including a field that looks like a length prefix), checks that
// each one decodes back to itself and that no two lists collide.
func TestEncodeAADInjective(t *testing.T) {
	alphabet := []string{"", "a", "b", "ab", "\x00\x00\x00\x01"}
	lists := [][]string{{}}
	for frontier := lists; len(frontier[0]) < 3; {
		var next [][]string
		for _, l := range frontier {
			for _, s := range alphabet {
				next = append(next, append(append([]string{}, l...), s))
			}
		}
		lists = append(lists, next...)
		frontier = next
	}
	seen := map[string][]string{}
	for _, l := range lists {
		enc := mustEncodeAAD(t, fieldsOf(l...)...)
		if dec, ok := decodeAAD(enc); !ok || !sameFields(dec, fieldsOf(l...)) {
			t.Fatalf("%q does not decode back to itself", l)
		}
		if prev, dup := seen[string(enc)]; dup {
			t.Fatalf("%q and %q encode to the same bytes", prev, l)
		}
		seen[string(enc)] = l
	}
	if want := 1 + 5 + 25 + 125; len(lists) != want {
		t.Fatalf("generated %d lists, want %d", len(lists), want)
	}
}
