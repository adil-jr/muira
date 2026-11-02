package crypto

import (
	"bytes"
	"errors"
	"testing"
)

// Fuzz targets. Seeds are added only with f.Add; nothing is stored under
// testdata/fuzz. No target runs Argon2: one derivation per execution would
// make fuzzing far too slow.

// fuzzOpenSeeds returns valid blobs under testKey and testAAD. They are
// built with fixed nonces so that every fuzzing process (the coordinator and
// each worker) derives exactly the same set.
func fuzzOpenSeeds(f *testing.F) [][]byte {
	f.Helper()
	pts := [][]byte{nil, testPT, bytes.Repeat([]byte{0xa5}, 64)}
	seeds := make([][]byte, 0, len(pts))
	for i, pt := range pts {
		nonce := bytes.Repeat([]byte{byte(i + 1)}, NonceSize)
		blob, err := sealWithNonce(testKey, nonce, pt, testAAD)
		if err != nil {
			f.Fatalf("sealWithNonce: %v", err)
		}
		seeds = append(seeds, blob)
	}
	return seeds
}

// FuzzOpen feeds arbitrary blobs to open with a fixed key and AAD. It must
// never panic, may only fail with ErrDecrypt or ErrUnsupportedVersion, and
// may only succeed on one of the valid seeds: any other blob that opens
// would be a forgery.
func FuzzOpen(f *testing.F) {
	seeds := fuzzOpenSeeds(f)
	valid := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		valid[string(s)] = true
		f.Add(s)
	}
	f.Add([]byte{})
	f.Add([]byte{FormatVersion})
	f.Add([]byte{0x02})
	f.Add(make([]byte, Overhead))
	f.Add(append([]byte{FormatVersion}, make([]byte, Overhead)...))

	f.Fuzz(func(t *testing.T, blob []byte) {
		pt, err := open(testKey, blob, testAAD)
		if err != nil {
			if !errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrUnsupportedVersion) {
				t.Fatalf("unexpected error: %v", err)
			}
			if pt != nil {
				t.Fatal("plaintext returned together with an error")
			}
			return
		}
		if !valid[string(blob)] {
			t.Fatalf("forgery: a blob that is not a valid seed opened (%d bytes)", len(blob))
		}
	})
}

// fieldsFrom derives an AAD field list from arbitrary bytes: the input is
// read as a sequence of (length byte, field bytes) pairs, where the field
// length is the length byte mod 8 and the field is the next that many bytes
// (fewer if the input ends first). So any byte string maps to a list with
// any number of fields, empty fields and fields holding any byte values,
// including bytes that look like length prefixes.
func fieldsFrom(data []byte) [][]byte {
	var fields [][]byte
	for len(data) > 0 {
		n := min(int(data[0]%8), len(data)-1)
		fields = append(fields, data[1:1+n])
		data = data[1+n:]
	}
	return fields
}

// FuzzAAD checks injectivity on lists derived from the input: two lists
// encode to the same bytes if and only if they are equal, and every
// encoding decodes back to its own list.
func FuzzAAD(f *testing.F) {
	f.Add([]byte{2, 'a', 'b', 1, 'c'}, []byte{1, 'a', 2, 'b', 'c'}) // ["ab","c"] vs ["a","bc"]
	f.Add([]byte{}, []byte{0})                                      // [] vs [""]
	f.Add([]byte{0, 0}, []byte{0})                                  // ["",""] vs [""]
	f.Add([]byte{4, 0, 0, 0, 1}, []byte{4, 0, 0, 0, 1})             // field that looks like a prefix

	f.Fuzz(func(t *testing.T, a, b []byte) {
		la, lb := fieldsFrom(a), fieldsFrom(b)
		ea, err := encodeAAD(la...)
		if err != nil {
			t.Fatalf("encodeAAD: %v", err)
		}
		eb, err := encodeAAD(lb...)
		if err != nil {
			t.Fatalf("encodeAAD: %v", err)
		}
		if bytes.Equal(ea, eb) != sameFields(la, lb) {
			t.Fatalf("lists %q and %q: equal encodings=%v, equal lists=%v",
				la, lb, bytes.Equal(ea, eb), sameFields(la, lb))
		}
		for _, c := range []struct {
			list [][]byte
			enc  []byte
		}{{la, ea}, {lb, eb}} {
			if dec, ok := decodeAAD(c.enc); !ok || !sameFields(dec, c.list) {
				t.Fatalf("%q does not decode back to itself", c.list)
			}
		}
	})
}

// FuzzRoundTrip seals arbitrary plaintext and AAD and opens them back.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(testPT, testAAD)
	f.Add(make([]byte, 100), []byte{FormatVersion})

	f.Fuzz(func(t *testing.T, pt, aad []byte) {
		blob, err := seal(testKey, pt, aad)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if len(blob) != Overhead+len(pt) {
			t.Fatalf("blob is %d bytes, want %d", len(blob), Overhead+len(pt))
		}
		got, err := open(testKey, blob, aad)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("round trip changed the plaintext")
		}
	})
}
