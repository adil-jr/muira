package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

// kdfParams returns cheap Argon2id parameters under -short and the
// production defaults otherwise. Production code never uses it.
func kdfParams(tb testing.TB) Params {
	tb.Helper()
	if testing.Short() {
		return Params{Time: 1, MemoryKiB: 64, Threads: 1, KeyLen: KeySize}
	}
	return DefaultParams()
}

// readTestdata reads a file from the repository-level testdata/ directory.
// The files there are official vectors and are never modified by tests.
func readTestdata(tb testing.TB, rel string) []byte {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", filepath.FromSlash(rel)))
	if err != nil {
		tb.Fatalf("read testdata: %v", err)
	}
	return b
}
