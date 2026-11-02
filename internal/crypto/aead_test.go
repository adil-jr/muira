package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// Property tests. They never produce expected ciphertexts: those come only
// from the NIST vectors in aead_kat_test.go.

var (
	testKey = bytes.Repeat([]byte{0x42}, KeySize)
	testAAD = []byte("aad")
	testPT  = []byte("attack at dawn")
)

func mustSeal(t *testing.T, key, pt, aad []byte) []byte {
	t.Helper()
	blob, err := seal(key, pt, aad)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return blob
}

// requireDecryptErr checks for the opaque error: ErrDecrypt with its bare
// message (never wrapped with details), and no plaintext.
func requireDecryptErr(t *testing.T, what string, pt []byte, err error) {
	t.Helper()
	if !errors.Is(err, ErrDecrypt) || err.Error() != ErrDecrypt.Error() {
		t.Errorf("%s: got err %v, want the bare ErrDecrypt", what, err)
	}
	if pt != nil {
		t.Errorf("%s: plaintext returned on failure", what)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	for _, pt := range [][]byte{nil, {}, {0}, testPT, bytes.Repeat([]byte{7}, 1000)} {
		blob := mustSeal(t, testKey, pt, testAAD)
		if len(blob) != Overhead+len(pt) {
			t.Fatalf("blob is %d bytes, want %d", len(blob), Overhead+len(pt))
		}
		if blob[0] != FormatVersion {
			t.Fatalf("version byte %#x, want %#x", blob[0], FormatVersion)
		}
		got, err := open(testKey, blob, testAAD)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip of %d bytes changed the plaintext", len(pt))
		}
	}
}

func TestOpenEveryByteFlip(t *testing.T) {
	blob := mustSeal(t, testKey, testPT, testAAD)
	for i := range blob {
		tampered := bytes.Clone(blob)
		tampered[i] ^= 0x01
		pt, err := open(testKey, tampered, testAAD)
		if i == 0 {
			if !errors.Is(err, ErrUnsupportedVersion) || pt != nil {
				t.Errorf("flip of the version byte: got %v, want ErrUnsupportedVersion", err)
			}
			continue
		}
		requireDecryptErr(t, fmt.Sprintf("flip of byte %d", i), pt, err)
	}
}

func TestOpenWrongAADOrKey(t *testing.T) {
	blob := mustSeal(t, testKey, testPT, testAAD)
	otherKey := bytes.Clone(testKey)
	otherKey[0] ^= 0x01

	pt, err := open(testKey, blob, []byte("aae"))
	requireDecryptErr(t, "different AAD", pt, err)
	pt, err = open(testKey, blob, nil)
	requireDecryptErr(t, "missing AAD", pt, err)
	pt, err = open(otherKey, blob, testAAD)
	requireDecryptErr(t, "wrong key", pt, err)
}

func TestOpenTruncated(t *testing.T) {
	blob := mustSeal(t, testKey, testPT, testAAD)
	for n := range len(blob) {
		pt, err := open(testKey, blob[:n], testAAD)
		requireDecryptErr(t, fmt.Sprintf("truncated to %d bytes", n), pt, err)
	}
}

// TestOpenCheckOrder pins the order fixed by ADR 0002: empty blob, then the
// version byte, then the minimum size, then GCM.
func TestOpenCheckOrder(t *testing.T) {
	pt, err := open(testKey, nil, testAAD)
	requireDecryptErr(t, "empty blob", pt, err)

	for _, v := range []byte{0x00, 0x02, 0xff} {
		// A lone unknown version byte is reported as unsupported, not as short.
		if _, err = open(testKey, []byte{v}, testAAD); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("version %#x: got %v, want ErrUnsupportedVersion", v, err)
		}
		blob := mustSeal(t, testKey, testPT, testAAD)
		blob[0] = v
		if _, err = open(testKey, blob, testAAD); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("full blob with version %#x: got %v, want ErrUnsupportedVersion", v, err)
		}
	}

	short := make([]byte, Overhead-1)
	short[0] = FormatVersion
	pt, err = open(testKey, short, testAAD)
	requireDecryptErr(t, "one byte below Overhead", pt, err)

	// Exactly Overhead bytes is a valid size (empty plaintext); a forged one
	// still fails authentication.
	forged := make([]byte, Overhead)
	forged[0] = FormatVersion
	pt, err = open(testKey, forged, testAAD)
	requireDecryptErr(t, "forged Overhead-sized blob", pt, err)
}

func TestNoncesAreDistinct(t *testing.T) {
	const n = 1000
	nonces := make(map[string]bool, n)
	for range n {
		blob := mustSeal(t, testKey, testPT, testAAD)
		nonce := string(blob[1 : 1+NonceSize])
		if nonces[nonce] {
			t.Fatal("nonce repeated")
		}
		nonces[nonce] = true
	}
}

func TestAEADKeyLength(t *testing.T) {
	blob := mustSeal(t, testKey, testPT, testAAD)
	for _, n := range []int{0, 16, 24, KeySize - 1, KeySize + 1} {
		key := make([]byte, n)
		if _, err := seal(key, testPT, testAAD); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("seal with %d-byte key: got %v, want ErrInvalidLength", n, err)
		}
		if _, err := open(key, blob, testAAD); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("open with %d-byte key: got %v, want ErrInvalidLength", n, err)
		}
	}
}
