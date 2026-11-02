package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

const argon2KATFile = "argon2/argon2id-v13.test.c.txt"

// argon2Vector is one hashtest(...) call from phc-winner-argon2 src/test.c.
type argon2Vector struct {
	time      uint32
	logMemory uint32 // log2 of the memory in KiB
	threads   uint8
	password  string
	salt      string
	want      []byte // hexref decoded
	mcf       string // mcfref, the two adjacent C literals concatenated
}

// hashtestRE matches one call, which spans 4 lines in the file:
//
//	hashtest(version, T, LOGM, P, "PWD", "SALT",
//	         "HEXREF",
//	         "MCF-PART-1"
//	         "MCF-PART-2", Argon2_id);
//
// \s also matches newlines, and the two adjacent literals are captured
// separately so they can be concatenated as the C compiler would.
var hashtestRE = regexp.MustCompile(
	`hashtest\(version,\s*(\d+),\s*(\d+),\s*(\d+),\s*"([^"]*)",\s*"([^"]*)",` +
		`\s*"([0-9a-f]+)",\s*"([^"]*)"\s*"([^"]*)",\s*Argon2_id\);`)

func loadArgon2Vectors(t *testing.T) []argon2Vector {
	t.Helper()
	src := string(readTestdata(t, argon2KATFile))
	matches := hashtestRE.FindAllStringSubmatch(src, -1)
	// Every call in the file must be parsed: none may be silently skipped.
	if calls := strings.Count(src, "hashtest("); len(matches) != calls {
		t.Fatalf("parsed %d hashtest calls, file has %d", len(matches), calls)
	}
	vectors := make([]argon2Vector, 0, len(matches))
	for _, m := range matches {
		var v argon2Vector
		mustScan(t, m[1], &v.time)
		mustScan(t, m[2], &v.logMemory)
		mustScan(t, m[3], &v.threads)
		v.password, v.salt = m[4], m[5]
		want, err := hex.DecodeString(m[6])
		if err != nil {
			t.Fatalf("hexref %q: %v", m[6], err)
		}
		v.want = want
		v.mcf = m[7] + m[8]
		vectors = append(vectors, v)
	}
	return vectors
}

func mustScan(t *testing.T, s string, dst any) {
	t.Helper()
	if _, err := fmt.Sscan(s, dst); err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
}

func TestArgon2idKATFileHasEightVectors(t *testing.T) {
	if n := len(loadArgon2Vectors(t)); n != 8 {
		t.Fatalf("got %d Argon2id vectors, want exactly 8", n)
	}
}

// TestArgon2idKATEncodingsAgree checks the parser: the numeric arguments,
// salt and hexref of each call must match its own PHC string (mcfref), which
// encodes the same values independently.
func TestArgon2idKATEncodingsAgree(t *testing.T) {
	b64 := base64.RawStdEncoding
	for _, v := range loadArgon2Vectors(t) {
		parts := strings.Split(v.mcf, "$")
		// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
		if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
			t.Fatalf("unexpected mcf %q", v.mcf)
		}
		var m, tm uint32
		var p uint8
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &tm, &p); err != nil {
			t.Fatalf("mcf params %q: %v", parts[3], err)
		}
		if m != 1<<v.logMemory || tm != v.time || p != v.threads {
			t.Errorf("mcf %q disagrees with t=%d logm=%d p=%d", v.mcf, v.time, v.logMemory, v.threads)
		}
		if salt, err := b64.DecodeString(parts[4]); err != nil || string(salt) != v.salt {
			t.Errorf("mcf salt %q does not decode to %q (err %v)", parts[4], v.salt, err)
		}
		if hash, err := b64.DecodeString(parts[5]); err != nil || !bytes.Equal(hash, v.want) {
			t.Errorf("mcf hash %q does not match hexref (err %v)", parts[5], err)
		}
	}
}

// TestArgon2idKAT checks deriveKey against the official phc-winner-argon2
// vectors. The expected values come only from testdata/.
func TestArgon2idKAT(t *testing.T) {
	for _, v := range loadArgon2Vectors(t) {
		name := fmt.Sprintf("t=%d,m=2^%d,p=%d,%s,%s", v.time, v.logMemory, v.threads, v.password, v.salt)
		t.Run(name, func(t *testing.T) {
			if testing.Short() && v.logMemory >= 18 {
				t.Skip("256 MiB vector skipped in -short mode")
			}
			if len(v.want) != KeySize {
				t.Fatalf("vector output is %d bytes, want %d", len(v.want), KeySize)
			}
			p := Params{Time: v.time, MemoryKiB: 1 << v.logMemory, Threads: v.threads, KeyLen: KeySize}
			got, err := deriveKey([]byte(v.password), []byte(v.salt), p)
			if err != nil {
				t.Fatalf("deriveKey: %v", err)
			}
			if !bytes.Equal(got, v.want) {
				t.Fatalf("got %x, want %x", got, v.want)
			}
		})
	}
}

func TestDeriveKeySaltLength(t *testing.T) {
	for _, n := range []int{0, SaltSize - 1, SaltSize + 1} {
		_, err := DeriveKey([]byte("pw"), make([]byte, n), kdfParams(t))
		if !errors.Is(err, ErrInvalidLength) {
			t.Errorf("salt of %d bytes: got %v, want ErrInvalidLength", n, err)
		}
	}
}

func TestDeriveKeyInvalidParams(t *testing.T) {
	p := kdfParams(t)
	p.Time = 0
	key, err := DeriveKey([]byte("pw"), make([]byte, SaltSize), p)
	if !errors.Is(err, ErrInvalidParams) || key != nil {
		t.Fatalf("got key=%v err=%v, want nil and ErrInvalidParams", key != nil, err)
	}
}

// TestDeriveKeyProperties checks determinism and input sensitivity. It does
// not produce expected values: those come only from the KAT above.
func TestDeriveKeyProperties(t *testing.T) {
	p := kdfParams(t)
	pw, salt := []byte("correct horse"), bytes.Repeat([]byte{0x5a}, SaltSize)
	derive := func(pw, salt []byte) []byte {
		t.Helper()
		k, err := DeriveKey(pw, salt, p)
		if err != nil {
			t.Fatalf("DeriveKey: %v", err)
		}
		return k
	}
	k1 := derive(pw, salt)
	if len(k1) != KeySize {
		t.Fatalf("key length %d, want %d", len(k1), KeySize)
	}
	if !bytes.Equal(k1, derive(pw, salt)) {
		t.Error("same inputs gave different keys")
	}
	if bytes.Equal(k1, derive([]byte("correct horsf"), salt)) {
		t.Error("different passwords gave the same key")
	}
	otherSalt := bytes.Clone(salt)
	otherSalt[SaltSize-1] ^= 1
	if bytes.Equal(k1, derive(pw, otherSalt)) {
		t.Error("different salts gave the same key")
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	pw, salt, p := []byte("correct horse battery staple"), NewSalt(), DefaultParams()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DeriveKey(pw, salt, p); err != nil {
			b.Fatal(err)
		}
	}
}
