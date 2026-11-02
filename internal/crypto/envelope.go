package crypto

import (
	"encoding/binary"
	"fmt"
)

// dekLabel is the domain label that starts every DEK AAD, so a wrapped DEK
// never authenticates as a record, and a record never as a wrapped DEK,
// even under the same key.
const dekLabel = "muira/dek"

// dekAAD returns the AAD of a wrapped DEK (ADR 0002): "muira/dek", format
// version, t (u32 BE), m in KiB (u32 BE), p (1 byte), keyLen (u32 BE) and
// salt, length-prefixed. Binding the KDF parameters and the salt means that
// tampering with the vault metadata makes unwrapping fail instead of
// silently weakening the KDF.
func dekAAD(salt []byte, p Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("%w: salt", ErrInvalidLength)
	}
	var t, m, keyLen [4]byte
	binary.BigEndian.PutUint32(t[:], p.Time)
	binary.BigEndian.PutUint32(m[:], p.MemoryKiB)
	binary.BigEndian.PutUint32(keyLen[:], p.KeyLen)
	return encodeAAD([]byte(dekLabel), []byte{FormatVersion},
		t[:], m[:], []byte{p.Threads}, keyLen[:], salt)
}

// WrapDEK encrypts the DEK under the KEK derived from the master password,
// bound to the salt and KDF parameters that produced that KEK. kek and dek
// must be KeySize bytes, salt SaltSize bytes, and p must pass Validate.
func WrapDEK(kek, dek, salt []byte, p Params) ([]byte, error) {
	aad, err := dekAAD(salt, p)
	if err != nil {
		return nil, err
	}
	if len(dek) != KeySize {
		return nil, fmt.Errorf("%w: DEK", ErrInvalidLength)
	}
	return seal(kek, dek, aad)
}

// UnwrapDEK decrypts a DEK wrapped by WrapDEK with the same KEK, salt and
// parameters. A wrong password, a tampered salt or parameters, or any other
// authentication failure is the opaque ErrDecrypt.
func UnwrapDEK(kek, wrapped, salt []byte, p Params) ([]byte, error) {
	aad, err := dekAAD(salt, p)
	if err != nil {
		return nil, err
	}
	dek, err := open(kek, wrapped, aad)
	if err != nil {
		return nil, err
	}
	if len(dek) != KeySize {
		// Authenticated, but not a DEK: never hand it out.
		Zero(dek)
		return nil, ErrDecrypt
	}
	return dek, nil
}
