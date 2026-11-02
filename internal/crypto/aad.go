package crypto

import (
	"encoding/binary"
	"fmt"
	"math"
)

// encodeAAD encodes fields as the concatenation of
// uint32 big-endian length ‖ bytes, one per field (ADR 0002). Because every
// length comes before its bytes, the encoding parses back deterministically
// and is injective: different field lists never produce the same AAD.
//
// A field longer than math.MaxUint32 bytes cannot be encoded and is an
// error. The check compares in uint64, so it is correct on 32-bit and
// 64-bit platforms alike.
func encodeAAD(fields ...[]byte) ([]byte, error) {
	var out []byte
	for _, f := range fields {
		n := uint64(len(f))
		if n > math.MaxUint32 {
			return nil, fmt.Errorf("%w: AAD field too long", ErrInvalidLength)
		}
		out = binary.BigEndian.AppendUint32(out, uint32(n))
		out = append(out, f...)
	}
	return out, nil
}
