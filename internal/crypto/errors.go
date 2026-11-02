package crypto

import "errors"

// Errors returned by this package. They never carry secret material
// (passwords, keys, salts, nonces or plaintext); callers compare them with
// errors.Is.
var (
	// ErrInvalidParams reports KDF parameters outside the accepted limits.
	// It is wrapped with the name of the offending field.
	ErrInvalidParams = errors.New("crypto: invalid KDF parameters")

	// ErrInvalidLength reports a key, salt or record ID of the wrong size.
	ErrInvalidLength = errors.New("crypto: invalid key, salt or ID length")
)
