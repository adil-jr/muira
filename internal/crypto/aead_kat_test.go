package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	gcmEncryptFile = "nist-gcm/gcmEncryptExtIV256.rsp"
	gcmDecryptFile = "nist-gcm/gcmDecrypt256.rsp"
)

// gcmVector is one case from a NIST CAVP GCM .rsp file.
type gcmVector struct {
	name                      string // section and Count, for messages
	ptBits, aadBits           int    // from the section header
	key, iv, pt, aad, ct, tag []byte
	fields                    map[string]bool // fields present in the case
	fail                      bool            // decrypt file: the case must be rejected
}

// inScope reports whether a section header set is the one muira uses:
// 256-bit key, 96-bit IV, 128-bit tag.
func inScope(h map[string]string) bool {
	return h["Keylen"] == "256" && h["IVlen"] == "96" && h["Taglen"] == "128"
}

// loadGCMVectors parses a .rsp file and returns the cases of the in-scope
// sections. Lines may end in CRLF (the files are stored unchanged); the \r
// is dropped while reading and the file itself is never modified.
//
// No in-scope case can be silently dropped: every case of the file must be
// seen, every line inside an in-scope case must be a known field or FAIL,
// and every returned case must be complete and consistent with its header.
func loadGCMVectors(t *testing.T, file string) []*gcmVector {
	t.Helper()
	src := string(readTestdata(t, file))
	header := map[string]string{}
	var (
		vectors []*gcmVector
		cur     *gcmVector
		seen    int // every case of the file, in scope or not
	)
	flush := func() {
		if cur != nil {
			vectors = append(vectors, cur)
			cur = nil
		}
	}
	for i, line := range strings.Split(src, "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			flush()
		case strings.HasPrefix(line, "["):
			flush()
			name, value, ok := strings.Cut(strings.Trim(line, "[]"), " = ")
			if !ok {
				t.Fatalf("%s:%d: bad header %q", file, i+1, line)
			}
			header[name] = value
		case strings.HasPrefix(line, "Count = "):
			flush()
			seen++
			if inScope(header) {
				cur = &gcmVector{
					name:   fmt.Sprintf("PTlen=%s,AADlen=%s,%s", header["PTlen"], header["AADlen"], line),
					fields: map[string]bool{},
				}
				mustScan(t, header["PTlen"], &cur.ptBits)
				mustScan(t, header["AADlen"], &cur.aadBits)
			}
		case cur == nil:
			if inScope(header) {
				t.Fatalf("%s:%d: line outside a case: %q", file, i+1, line)
			}
		case line == "FAIL":
			cur.fail = true
		default:
			parseGCMField(t, cur, fmt.Sprintf("%s:%d", file, i+1), line)
		}
	}
	flush()
	if want := strings.Count(src, "Count = "); seen != want {
		t.Fatalf("%s: parser saw %d cases, file has %d", file, seen, want)
	}
	for _, v := range vectors {
		checkGCMVector(t, file, v)
	}
	return vectors
}

func parseGCMField(t *testing.T, v *gcmVector, pos, line string) {
	t.Helper()
	name, value, ok := strings.Cut(line, " = ")
	if !ok {
		t.Fatalf("%s: unexpected line %q", pos, line)
	}
	dst := map[string]*[]byte{
		"Key": &v.key, "IV": &v.iv, "PT": &v.pt, "AAD": &v.aad, "CT": &v.ct, "Tag": &v.tag,
	}[name]
	if dst == nil || v.fields[name] {
		t.Fatalf("%s: unknown or repeated field %q", pos, name)
	}
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: field %s: %v", pos, name, err)
	}
	*dst = b
	v.fields[name] = true
}

// checkGCMVector rejects incomplete cases and cases whose sizes disagree with
// the section header, so a parser bug cannot pass as a valid vector.
func checkGCMVector(t *testing.T, file string, v *gcmVector) {
	t.Helper()
	for _, f := range []string{"Key", "IV", "AAD", "CT", "Tag"} {
		if !v.fields[f] {
			t.Fatalf("%s %s: missing %s", file, v.name, f)
		}
	}
	if v.fields["PT"] == v.fail {
		t.Fatalf("%s %s: PT present=%v but FAIL=%v", file, v.name, v.fields["PT"], v.fail)
	}
	switch {
	case len(v.key) != KeySize, len(v.iv) != NonceSize, len(v.tag) != TagSize,
		8*len(v.ct) != v.ptBits, 8*len(v.aad) != v.aadBits,
		v.fields["PT"] && len(v.pt) != len(v.ct):
		t.Fatalf("%s %s: sizes disagree with the section header", file, v.name)
	}
}

// gcmBlob builds the expected muira blob for a vector:
// version ‖ IV ‖ CT ‖ Tag.
func gcmBlob(v *gcmVector) []byte {
	blob := []byte{FormatVersion}
	blob = append(blob, v.iv...)
	blob = append(blob, v.ct...)
	return append(blob, v.tag...)
}

func countGCM(vectors []*gcmVector) (normal, fail int) {
	for _, v := range vectors {
		if v.fail {
			fail++
		} else {
			normal++
		}
	}
	return normal, fail
}

// TestGCMKATFiles pins the exact number of in-scope cases, so a bug in the
// scope filter cannot pass. The numbers come from the official files,
// counted with a method independent of this parser (awk over the .rsp files
// with CR removed): 25 in-scope sections of 15 cases per file.
func TestGCMKATFiles(t *testing.T) {
	const (
		wantEncNormal, wantEncFail = 375, 0
		wantDecNormal, wantDecFail = 184, 191
	)
	encNormal, encFail := countGCM(loadGCMVectors(t, gcmEncryptFile))
	decNormal, decFail := countGCM(loadGCMVectors(t, gcmDecryptFile))
	if encNormal != wantEncNormal || encFail != wantEncFail {
		t.Errorf("encrypt file: %d normal and %d FAIL cases, want %d and %d",
			encNormal, encFail, wantEncNormal, wantEncFail)
	}
	if decNormal != wantDecNormal || decFail != wantDecFail {
		t.Errorf("decrypt file: %d normal and %d FAIL cases, want %d and %d",
			decNormal, decFail, wantDecNormal, wantDecFail)
	}
}

// TestGCMEncryptKAT compares the whole blob, version byte included, with the
// official IV, CT and Tag. Expected values come only from testdata/.
func TestGCMEncryptKAT(t *testing.T) {
	for _, v := range loadGCMVectors(t, gcmEncryptFile) {
		got, err := sealWithNonce(v.key, v.iv, v.pt, v.aad)
		if err != nil {
			t.Fatalf("%s: sealWithNonce: %v", v.name, err)
		}
		if want := gcmBlob(v); !bytes.Equal(got, want) {
			t.Errorf("%s: blob mismatch\n got %x\nwant %x", v.name, got, want)
		}
	}
}

// TestGCMDecryptKAT opens the official ciphertexts: normal cases must give
// back PT, and FAIL cases must give the opaque ErrDecrypt.
func TestGCMDecryptKAT(t *testing.T) {
	for _, v := range loadGCMVectors(t, gcmDecryptFile) {
		got, err := open(v.key, gcmBlob(v), v.aad)
		switch {
		case v.fail && !errors.Is(err, ErrDecrypt):
			t.Errorf("%s: FAIL case: got err %v, want ErrDecrypt", v.name, err)
		case v.fail && got != nil:
			t.Errorf("%s: FAIL case returned plaintext", v.name)
		case !v.fail && err != nil:
			t.Errorf("%s: open: %v", v.name, err)
		case !v.fail && !bytes.Equal(got, v.pt):
			t.Errorf("%s: plaintext mismatch", v.name)
		}
	}
}
