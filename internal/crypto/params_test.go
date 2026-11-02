package crypto

import (
	"errors"
	"testing"
)

// validParams is a parameter set that passes Validate; each case changes one field.
var validParams = Params{Time: 1, MemoryKiB: 64, Threads: 1, KeyLen: KeySize}

func TestDefaultParams(t *testing.T) {
	// The table in ADR 0002: t=3, m=64 MiB, p=4, 32-byte output.
	want := Params{Time: 3, MemoryKiB: 65536, Threads: 4, KeyLen: 32}
	if got := DefaultParams(); got != want {
		t.Fatalf("DefaultParams() = %+v, want %+v", got, want)
	}
	if err := DefaultParams().ValidateNew(); err != nil {
		t.Fatalf("DefaultParams().ValidateNew() = %v", err)
	}
}

func TestDefaultParamsCannotBeMutated(t *testing.T) {
	p := DefaultParams()
	p.Time, p.MemoryKiB, p.Threads, p.KeyLen = 1, 8, 1, 16
	if DefaultParams() == p {
		t.Fatal("changing a returned value changed the defaults")
	}
}

func TestValidate(t *testing.T) {
	with := func(f func(*Params)) Params {
		p := validParams
		f(&p)
		return p
	}
	tests := []struct {
		name string
		p    Params
		ok   bool
	}{
		{"valid", validParams, true},
		{"keylen 31", with(func(p *Params) { p.KeyLen = 31 }), false},
		{"keylen 33", with(func(p *Params) { p.KeyLen = 33 }), false},
		{"time 0", with(func(p *Params) { p.Time = 0 }), false},
		{"time 1", with(func(p *Params) { p.Time = 1 }), true},
		{"time 64", with(func(p *Params) { p.Time = 64 }), true},
		{"time 65", with(func(p *Params) { p.Time = 65 }), false},
		{"threads 0", with(func(p *Params) { p.Threads = 0; p.MemoryKiB = 64 }), false},
		{"memory 8p-1, p=1", with(func(p *Params) { p.Threads = 1; p.MemoryKiB = 7 }), false},
		{"memory 8p, p=1", with(func(p *Params) { p.Threads = 1; p.MemoryKiB = 8 }), true},
		{"memory 1 GiB", with(func(p *Params) { p.MemoryKiB = 1 << 20 }), true},
		{"memory 1 GiB + 1", with(func(p *Params) { p.MemoryKiB = 1<<20 + 1 }), false},
		// 8*Threads must not wrap around in uint8 (it would from Threads=32).
		{"memory 8p-1, p=32", with(func(p *Params) { p.Threads = 32; p.MemoryKiB = 255 }), false},
		{"memory 8p, p=32", with(func(p *Params) { p.Threads = 32; p.MemoryKiB = 256 }), true},
		{"memory 8p-1, p=255", with(func(p *Params) { p.Threads = 255; p.MemoryKiB = 2039 }), false},
		{"memory 8p, p=255", with(func(p *Params) { p.Threads = 255; p.MemoryKiB = 2040 }), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkParamsErr(t, tc.p.Validate(), tc.ok)
		})
	}
}

func TestValidateNew(t *testing.T) {
	base := Params{Time: 2, MemoryKiB: 19456, Threads: 1, KeyLen: KeySize}
	tests := []struct {
		name string
		p    Params
		ok   bool
	}{
		{"minimum", base, true},
		{"time 1", Params{Time: 1, MemoryKiB: 19456, Threads: 1, KeyLen: KeySize}, false},
		{"memory 19455", Params{Time: 2, MemoryKiB: 19455, Threads: 1, KeyLen: KeySize}, false},
		{"fails Validate", Params{Time: 2, MemoryKiB: 19456, Threads: 1, KeyLen: 16}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkParamsErr(t, tc.p.ValidateNew(), tc.ok)
		})
	}
}

func checkParamsErr(t *testing.T, err error, ok bool) {
	t.Helper()
	switch {
	case ok && err != nil:
		t.Fatalf("got error %v, want nil", err)
	case !ok && !errors.Is(err, ErrInvalidParams):
		t.Fatalf("got error %v, want ErrInvalidParams", err)
	}
}
