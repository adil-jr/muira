package crypto

// Zero overwrites every buffer with zeros using clear.
//
// This is best effort only: the bytes may already have been copied (stack
// growth, an append that reallocated, a conversion to string elsewhere), and
// memory the runtime frees is not zeroed. Zero cannot guarantee that no copy
// of a secret remains in memory or swap.
func Zero(bufs ...[]byte) {
	for _, b := range bufs {
		clear(b)
	}
}
