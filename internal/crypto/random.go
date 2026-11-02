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
