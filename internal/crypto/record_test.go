package crypto

import (
	"bytes"
	"errors"
	"testing"
)

var testRecordID = bytes.Repeat([]byte{0x07}, RecordIDSize)

func mustSealRecord(t *testing.T, dek, id, pt []byte) []byte {
	t.Helper()
	blob, err := SealRecord(dek, id, pt)
	if err != nil {
		t.Fatalf("SealRecord: %v", err)
	}
	return blob
}

func TestRecordRoundTrip(t *testing.T) {
	for _, pt := range [][]byte{nil, testPT} {
		blob := mustSealRecord(t, testKey, testRecordID, pt)
		got, err := OpenRecord(testKey, testRecordID, blob)
		if err != nil {
			t.Fatalf("OpenRecord: %v", err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatal("round trip changed the plaintext")
		}
	}
}

func TestRecordIDLength(t *testing.T) {
	blob := mustSealRecord(t, testKey, testRecordID, testPT)
	for _, n := range []int{0, RecordIDSize - 1, RecordIDSize + 1} {
		id := make([]byte, n)
		if _, err := SealRecord(testKey, id, testPT); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("SealRecord with %d-byte ID: got %v, want ErrInvalidLength", n, err)
		}
		if _, err := OpenRecord(testKey, id, blob); !errors.Is(err, ErrInvalidLength) {
			t.Errorf("OpenRecord with %d-byte ID: got %v, want ErrInvalidLength", n, err)
		}
	}
}

func TestRecordDEKLength(t *testing.T) {
	if _, err := SealRecord(make([]byte, 16), testRecordID, testPT); !errors.Is(err, ErrInvalidLength) {
		t.Errorf("SealRecord with 16-byte DEK: got %v, want ErrInvalidLength", err)
	}
}

func TestOpenRecordRejects(t *testing.T) {
	otherID := NewRecordID()
	blob := mustSealRecord(t, testKey, testRecordID, testPT)
	otherBlob := mustSealRecord(t, testKey, otherID, []byte("other secret"))

	otherKey := bytes.Clone(testKey)
	otherKey[KeySize-1] ^= 0x80
	pt, err := OpenRecord(otherKey, testRecordID, blob)
	requireDecryptErr(t, "wrong DEK", pt, err)

	flippedID := bytes.Clone(testRecordID)
	flippedID[0] ^= 0x01
	pt, err = OpenRecord(testKey, flippedID, blob)
	requireDecryptErr(t, "changed record ID", pt, err)

	// A blob copied from another record into this one.
	pt, err = OpenRecord(testKey, testRecordID, otherBlob)
	requireDecryptErr(t, "blob of another record", pt, err)
}

// TestSealRecordAAD shows that a record blob is bound to exactly the record
// AAD: it opens with the hand-written AAD and with nothing else.
func TestSealRecordAAD(t *testing.T) {
	id := mustHex(t, "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")
	blob := mustSealRecord(t, testKey, id, testPT)

	exact := mustHex(t, ""+
		"00 00 00 0c 6d 75 69 72 61 2f 72 65 63 6f 72 64"+
		"00 00 00 01 01"+
		"00 00 00 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f")
	if got, err := open(testKey, blob, exact); err != nil || !bytes.Equal(got, testPT) {
		t.Fatalf("open with the hand-written record AAD: err %v", err)
	}

	others := map[string][]byte{
		"no AAD":         nil,
		"raw record ID":  id,
		"no version":     mustEncodeAAD(t, []byte(recordLabel), id),
		"other label":    mustEncodeAAD(t, []byte("muira/dek"), []byte{FormatVersion}, id),
		"plain concat":   append(append([]byte(recordLabel), FormatVersion), id...),
		"other version":  mustEncodeAAD(t, []byte(recordLabel), []byte{0x02}, id),
		"label, version": mustEncodeAAD(t, []byte(recordLabel), []byte{FormatVersion}),
	}
	for name, aad := range others {
		pt, err := open(testKey, blob, aad)
		requireDecryptErr(t, name, pt, err)
	}
}
