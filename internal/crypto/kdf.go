package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// DeriveKey derives a key from password and salt with Argon2id (version
// 0x13). The salt must be SaltSize bytes and p must pass Validate.
func DeriveKey(password, salt []byte, p Params) ([]byte, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("%w: salt", ErrInvalidLength)
	}
	return deriveKey(password, salt, p)
}

// deriveKey is DeriveKey without the salt length check. It exists only for
// the known-answer tests, whose official vectors use 8-byte salts.
func deriveKey(password, salt []byte, p Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen), nil
}
