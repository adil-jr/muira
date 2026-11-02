package crypto

import "errors"

// Errors returned by this package. They never carry secret material
// (passwords, keys, salts, nonces or plaintext); callers compare them with
// errors.Is.
var (
	// ErrDecrypt reports that a blob could not be decrypted: wrong key or
	// password, tampering, truncation or a different AAD. It is opaque on
	// purpose: the cases are indistinguishable and it is never wrapped with
	// details.
	ErrDecrypt = errors.New("crypto: decryption failed")

	// ErrUnsupportedVersion reports a blob whose format version byte is not
	// FormatVersion.
	ErrUnsupportedVersion = errors.New("crypto: unsupported format version")

	// ErrInvalidParams reports KDF parameters outside the accepted limits.
	// It is wrapped with the name of the offending field.
	ErrInvalidParams = errors.New("crypto: invalid KDF parameters")

	// ErrInvalidLength reports a key, salt or record ID of the wrong size.
	ErrInvalidLength = errors.New("crypto: invalid key, salt or ID length")
)
