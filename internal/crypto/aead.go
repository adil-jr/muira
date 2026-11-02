package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Blob format (ADR 0002): version (1 byte) ‖ nonce (12) ‖ ciphertext ‖ tag (16).
const (
	// FormatVersion is the only blob format version this package reads and
	// writes.
	FormatVersion byte = 0x01
	// NonceSize is the size of the random AES-GCM nonce (96 bits).
	NonceSize = 12
	// TagSize is the size of the AES-GCM authentication tag (128 bits).
	TagSize = 16
	// Overhead is the number of bytes a blob adds to its plaintext.
	Overhead = 1 + NonceSize + TagSize
)

// newGCM returns AES-256-GCM for key, rejecting any key that is not KeySize
// bytes (AES-128 and AES-192 keys included).
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: key", ErrInvalidLength)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext under key with a fresh random nonce from
// crypto/rand and returns the blob. Callers never choose the nonce.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	_, _ = rand.Read(nonce)
	return sealWithNonce(key, nonce, plaintext, aad)
}

// sealWithNonce is seal with an explicit nonce. It exists only so the NIST
// known-answer tests can check the output byte for byte; nonce must be
// NonceSize bytes and must never be reused with the same key.
func sealWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 1+NonceSize, Overhead+len(plaintext))
	blob[0] = FormatVersion
	copy(blob[1:], nonce)
	return aead.Seal(blob, nonce, plaintext, aad), nil
}

// open authenticates and decrypts blob under key and aad. The checks run in
// the order fixed by ADR 0002, and every authentication failure is the
// opaque ErrDecrypt.
func open(key, blob, aad []byte) ([]byte, error) {
	switch {
	case len(blob) == 0:
		return nil, ErrDecrypt
	case blob[0] != FormatVersion:
		return nil, ErrUnsupportedVersion
	case len(blob) < Overhead:
		return nil, ErrDecrypt
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, blob[1:1+NonceSize], blob[1+NonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
