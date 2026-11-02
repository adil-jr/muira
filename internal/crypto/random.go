package crypto

import "crypto/rand"

// NewSalt returns SaltSize fresh random bytes from crypto/rand.
//
// It has no error path: since Go 1.24, crypto/rand.Read never returns an
// error (if the system source fails, the program aborts irrecoverably).
func NewSalt() []byte {
	b := make([]byte, SaltSize)
	_, _ = rand.Read(b)
	return b
}

// NewRecordID returns RecordIDSize fresh random bytes from crypto/rand, to
// be used as a record's storage key and in its AAD. Like NewSalt, it has no
// error path.
func NewRecordID() []byte {
	b := make([]byte, RecordIDSize)
	_, _ = rand.Read(b)
	return b
}

// NewDEK returns a fresh KeySize-byte data-encryption key from crypto/rand,
// generated once at vault init. Like NewSalt, it has no error path.
func NewDEK() []byte {
	b := make([]byte, KeySize)
	_, _ = rand.Read(b)
	return b
}
