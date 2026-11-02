package crypto

import "fmt"

// Sizes, in bytes, of the key material handled by this package.
const (
	// KeySize is the size of every derived or generated key (AES-256).
	KeySize = 32
	// SaltSize is the size of the Argon2id salt.
	SaltSize = 16
)

// Limits enforced by Validate and ValidateNew (ADR 0002).
const (
	maxTime         = 64
	maxMemoryKiB    = 1 << 20 // 1 GiB
	minNewTime      = 2
	minNewMemoryKiB = 19456 // OWASP minimum for Argon2id
)

// Params are the Argon2id cost parameters. They are stored in the vault
// metadata and always read back from it on unlock; DefaultParams is only
// used when creating new key material.
type Params struct {
	Time      uint32 // iterations (t)
	MemoryKiB uint32 // memory in KiB (m)
	Threads   uint8  // parallelism (p)
	KeyLen    uint32 // output length in bytes
}

// DefaultParams returns the production parameters for new key material:
// RFC 9106, section 4, second recommended option (t=3, m=64 MiB, p=4) with a
// 32-byte output. It returns a fresh value, so callers cannot change the
// defaults.
func DefaultParams() Params {
	return Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4, KeyLen: KeySize}
}

// Validate checks the structural and anti-DoS limits. It runs on every
// derivation, because the parameters are read from the vault metadata before
// anything has been authenticated.
func (p Params) Validate() error {
	switch {
	case p.KeyLen != KeySize:
		return fmt.Errorf("%w: key length", ErrInvalidParams)
	case p.Time < 1 || p.Time > maxTime:
		return fmt.Errorf("%w: time", ErrInvalidParams)
	case p.Threads < 1:
		return fmt.Errorf("%w: threads", ErrInvalidParams)
	// 8*Threads is computed in uint32: in uint8 it wraps from Threads=32 on.
	case p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("%w: memory", ErrInvalidParams)
	}
	return nil
}

// ValidateNew runs Validate and also enforces the minimum strength for new
// key material (vault init and password rotation).
func (p Params) ValidateNew() error {
	if err := p.Validate(); err != nil {
		return err
	}
	switch {
	case p.Time < minNewTime:
		return fmt.Errorf("%w: time below minimum", ErrInvalidParams)
	case p.MemoryKiB < minNewMemoryKiB:
		return fmt.Errorf("%w: memory below minimum", ErrInvalidParams)
	}
	return nil
}
