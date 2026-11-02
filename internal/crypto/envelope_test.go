package crypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
)

var (
	testSalt = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	testDEK  = bytes.Repeat([]byte{0x24}, KeySize)
)

// dekAADHand is the DEK AAD for DefaultParams() and salt 00..0f, written by
// hand from ADR 0002 (and cross-checked by the reviewer with an independent
// encoder): label, version, t, m, p, keyLen and salt, each with a uint32
// big-endian length prefix.
const dekAADHand = "" +
	"00 00 00 09 6d 75 69 72 61 2f 64 65 6b" + // "muira/dek"
	"00 00 00 01 01" + // version 0x01
	"00 00 00 04 00 00 00 03" + // t = 3
	"00 00 00 04 00 01 00 00" + // m = 65536 KiB
	"00 00 00 01 04" + // p = 4
	"00 00 00 04 00 00 00 20" + // keyLen = 32
	"00 00 00 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f" // salt

func mustWrap(t *testing.T, kek, dek, salt []byte, p Params) []byte {
	t.Helper()
	w, err := WrapDEK(kek, dek, salt, p)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	return w
}

func TestDEKAADBytes(t *testing.T) {
	got, err := dekAAD(testSalt, DefaultParams())
	if err != nil {
		t.Fatalf("dekAAD: %v", err)
	}
	if want := mustHex(t, dekAADHand); !bytes.Equal(got, want) {
		t.Fatalf("got %x\nwant %x", got, want)
	}
}

// TestWrapDEKAAD shows that a wrapped DEK is bound to exactly the DEK AAD:
// it opens with the hand-written AAD and with nothing else.
func TestWrapDEKAAD(t *testing.T) {
	p := DefaultParams()
	wrapped := mustWrap(t, testKey, testDEK, testSalt, p)

	if got, err := open(testKey, wrapped, mustHex(t, dekAADHand)); err != nil || !bytes.Equal(got, testDEK) {
		t.Fatalf("open with the hand-written DEK AAD: err %v", err)
	}

	u32 := func(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
	ver := []byte{FormatVersion}
	others := map[string][]byte{
		"no AAD":       nil,
		"salt only":    testSalt,
		"record label": mustEncodeAAD(t, []byte(recordLabel), ver, u32(3), u32(65536), []byte{4}, u32(32), testSalt),
		"no label":     mustEncodeAAD(t, ver, u32(3), u32(65536), []byte{4}, u32(32), testSalt),
		"no version":   mustEncodeAAD(t, []byte(dekLabel), u32(3), u32(65536), []byte{4}, u32(32), testSalt),
		"no salt":      mustEncodeAAD(t, []byte(dekLabel), ver, u32(3), u32(65536), []byte{4}, u32(32)),
		"p as u32":     mustEncodeAAD(t, []byte(dekLabel), ver, u32(3), u32(65536), u32(4), u32(32), testSalt),
		"t = 2":        mustEncodeAAD(t, []byte(dekLabel), ver, u32(2), u32(65536), []byte{4}, u32(32), testSalt),
	}
	for name, aad := range others {
		pt, err := open(testKey, wrapped, aad)
		requireDecryptErr(t, name, pt, err)
	}
}

func TestDEKRoundTrip(t *testing.T) {
	p := kdfParams(t)
	wrapped := mustWrap(t, testKey, testDEK, testSalt, p)
	got, err := UnwrapDEK(testKey, wrapped, testSalt, p)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, testDEK) {
		t.Fatal("unwrapped DEK differs")
	}
}

func TestWrapDEKInvalidInputs(t *testing.T) {
	p := kdfParams(t)
	bad := p
	bad.Time = 0
	wrapped := mustWrap(t, testKey, testDEK, testSalt, p)

	if _, err := WrapDEK(testKey, testDEK, testSalt, bad); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("WrapDEK with invalid params: got %v, want ErrInvalidParams", err)
	}
	if _, err := UnwrapDEK(testKey, wrapped, testSalt, bad); !errors.Is(err, ErrInvalidParams) {
		t.Errorf("UnwrapDEK with invalid params: got %v, want ErrInvalidParams", err)
	}

	for _, n := range []int{0, SaltSize - 1, SaltSize + 1} {
		salt := make([]byte, n)
		if _, err := WrapDEK(testKey, testDEK, salt, p); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("WrapDEK with %d-byte salt: got %v, want ErrInvalidLength", n, err)
		}
		if _, err := UnwrapDEK(testKey, wrapped, salt, p); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("UnwrapDEK with %d-byte salt: got %v, want ErrInvalidLength", n, err)
		}
	}
	for _, n := range []int{0, 16, KeySize - 1, KeySize + 1} {
		key := make([]byte, n)
		if _, err := WrapDEK(key, testDEK, testSalt, p); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("WrapDEK with %d-byte KEK: got %v, want ErrInvalidLength", n, err)
		}
		if _, err := UnwrapDEK(key, wrapped, testSalt, p); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("UnwrapDEK with %d-byte KEK: got %v, want ErrInvalidLength", n, err)
		}
		if _, err := WrapDEK(testKey, key, testSalt, p); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("WrapDEK with %d-byte DEK: got %v, want ErrInvalidLength", n, err)
		}
	}
}

// TestUnwrapDEKWrongSize: an authenticated payload that is not KeySize
// bytes is never returned as a DEK.
func TestUnwrapDEKWrongSize(t *testing.T) {
	p := kdfParams(t)
	aad, err := dekAAD(testSalt, p)
	if err != nil {
		t.Fatalf("dekAAD: %v", err)
	}
	for _, n := range []int{0, KeySize - 1, KeySize + 1} {
		blob, err := seal(testKey, bytes.Repeat([]byte{0x24}, n), aad)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		dek, err := UnwrapDEK(testKey, blob, testSalt, p)
		requireDecryptErr(t, fmt.Sprintf("authenticated payload of %d bytes", n), dek, err)
	}
}

func TestUnwrapDEKRejects(t *testing.T) {
	p := kdfParams(t)
	wrapped := mustWrap(t, testKey, testDEK, testSalt, p)

	otherKEK := bytes.Clone(testKey)
	otherKEK[3] ^= 0x10
	dek, err := UnwrapDEK(otherKEK, wrapped, testSalt, p)
	requireDecryptErr(t, "wrong KEK", dek, err)

	changed := map[string]Params{
		"time":    {Time: p.Time + 1, MemoryKiB: p.MemoryKiB, Threads: p.Threads, KeyLen: p.KeyLen},
		"memory":  {Time: p.Time, MemoryKiB: p.MemoryKiB * 2, Threads: p.Threads, KeyLen: p.KeyLen},
		"threads": {Time: p.Time, MemoryKiB: p.MemoryKiB, Threads: p.Threads + 1, KeyLen: p.KeyLen},
	}
	for field, q := range changed {
		if err = q.Validate(); err != nil {
			t.Fatalf("changed %s must still pass Validate: %v", field, err)
		}
		dek, err = UnwrapDEK(testKey, wrapped, testSalt, q)
		requireDecryptErr(t, "changed "+field, dek, err)
	}

	otherSalt := bytes.Clone(testSalt)
	otherSalt[SaltSize-1] ^= 0x01
	dek, err = UnwrapDEK(testKey, wrapped, otherSalt, p)
	requireDecryptErr(t, "changed salt", dek, err)
}

// TestDomainSeparation uses one key for both contexts, and the same 16 bytes
// as salt and as record ID, to show the labels alone keep them apart.
func TestDomainSeparation(t *testing.T) {
	p := kdfParams(t)
	same := testSalt // also a valid record ID

	wrapped := mustWrap(t, testKey, testDEK, same, p)
	for _, id := range [][]byte{same, testRecordID, NewRecordID()} {
		pt, err := OpenRecord(testKey, id, wrapped)
		requireDecryptErr(t, "wrapped DEK opened as a record", pt, err)
	}

	record := mustSealRecord(t, testKey, same, testDEK) // a 32-byte payload
	dek, err := UnwrapDEK(testKey, record, same, p)
	requireDecryptErr(t, "record opened as a wrapped DEK", dek, err)
}

// TestEnvelopeFlow runs the whole chain: password → KEK → wrapped DEK →
// record, then a password change that rewraps the same DEK.
func TestEnvelopeFlow(t *testing.T) {
	p := kdfParams(t)
	derive := func(pw, salt []byte) []byte {
		t.Helper()
		k, err := DeriveKey(pw, salt, p)
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}
		return k
	}
	unwrap := func(kek, wrapped, salt []byte) []byte {
		t.Helper()
		dek, err := UnwrapDEK(kek, wrapped, salt, p)
		if err != nil {
			t.Fatalf("UnwrapDEK: %v", err)
		}
		return dek
	}

	// init: new salt, KEK from the password, random DEK, one record.
	salt1, dek := NewSalt(), NewDEK()
	kek1 := derive([]byte("old password"), salt1)
	wrapped1 := mustWrap(t, kek1, dek, salt1, p)
	id := NewRecordID()
	record := mustSealRecord(t, unwrap(kek1, wrapped1, salt1), id, testPT)
	if got, err := OpenRecord(unwrap(kek1, wrapped1, salt1), id, record); err != nil || !bytes.Equal(got, testPT) {
		t.Fatalf("open record after unlock: err %v", err)
	}

	// rotate: new salt and KEK, the same DEK rewrapped; the record is untouched.
	salt2 := NewSalt()
	kek2 := derive([]byte("new password"), salt2)
	wrapped2 := mustWrap(t, kek2, unwrap(kek1, wrapped1, salt1), salt2, p)
	if got, err := OpenRecord(unwrap(kek2, wrapped2, salt2), id, record); err != nil || !bytes.Equal(got, testPT) {
		t.Fatalf("old record after password change: err %v", err)
	}

	// The old wrapping does not open with the new KEK (old or new salt),
	// and the new wrapping does not open with the old KEK.
	dek2, err := UnwrapDEK(kek2, wrapped1, salt1, p)
	requireDecryptErr(t, "old wrapping, new KEK", dek2, err)
	dek2, err = UnwrapDEK(kek2, wrapped1, salt2, p)
	requireDecryptErr(t, "old wrapping, new KEK and salt", dek2, err)
	dek2, err = UnwrapDEK(kek1, wrapped2, salt2, p)
	requireDecryptErr(t, "new wrapping, old KEK", dek2, err)
}
