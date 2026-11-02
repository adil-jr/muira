package crypto

import "fmt"

// RecordIDSize is the size of a random record ID (ADR 0002).
const RecordIDSize = 16

// recordLabel is the domain label that starts every record AAD, so a record
// blob never authenticates in another context, even under the same key.
const recordLabel = "muira/record"

// recordAAD returns the AAD of a record: "muira/record", format version and
// record ID, length-prefixed.
func recordAAD(recordID []byte) ([]byte, error) {
	if len(recordID) != RecordIDSize {
		return nil, fmt.Errorf("%w: record ID", ErrInvalidLength)
	}
	return encodeAAD([]byte(recordLabel), []byte{FormatVersion}, recordID)
}

// SealRecord encrypts a record's plaintext under the DEK, bound to its
// record ID. A blob moved to another record ID fails to open.
func SealRecord(dek, recordID, plaintext []byte) ([]byte, error) {
	aad, err := recordAAD(recordID)
	if err != nil {
		return nil, err
	}
	return seal(dek, plaintext, aad)
}

// OpenRecord decrypts a blob produced by SealRecord for the same DEK and
// record ID. Any authentication failure is the opaque ErrDecrypt.
func OpenRecord(dek, recordID, blob []byte) ([]byte, error) {
	aad, err := recordAAD(recordID)
	if err != nil {
		return nil, err
	}
	return open(dek, blob, aad)
}
