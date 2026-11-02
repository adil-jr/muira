// Package crypto implements key derivation (Argon2id), authenticated
// encryption (AES-256-GCM) and the versioned envelope format used by muira.
//
// It is the only package allowed to import crypto/* primitives and
// golang.org/x/crypto. It must not import internal/storage.
package crypto
