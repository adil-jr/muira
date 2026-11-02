package crypto

import (
	"bytes"
	"testing"
)

func TestZero(t *testing.T) {
	a := []byte{1, 2, 3}
	b := bytes.Repeat([]byte{0xff}, 40)
	Zero(a, nil, b)
	if !bytes.Equal(a, make([]byte, len(a))) || !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("buffers not zeroed: %v %v", a, b)
	}
	Zero() // no buffers: must not panic
}
