package crypto

// Zero overwrites every buffer with zeros using clear.
//
// This is best effort only: the Go runtime may already have copied the bytes
// (garbage collector, stack growth, conversions to string elsewhere), so
// Zero cannot guarantee that no copy of a secret remains in memory or swap.
func Zero(bufs ...[]byte) {
	for _, b := range bufs {
		clear(b)
	}
}
