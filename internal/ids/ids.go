// Package ids makes record identifiers: a short prefix naming the kind of
// record, an underscore, then a ULID. IDs therefore sort by creation time,
// tell their kind at a glance, and fit the schemas' id pattern.
package ids

import (
	"crypto/rand"
	"time"
)

// Prefixes of the records the box creates.
const (
	Grant    = "grt"
	Consent  = "cns"
	Decision = "dec"
	Approval = "apr"
)

// Crockford's base32, as ULIDs use it.
const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns prefix_ULID for the current time.
func New(prefix string) string { return At(prefix, time.Now()) }

// At returns prefix_ULID for the given time.
func At(prefix string, t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli()) // #nosec G115 -- times before 1970 do not occur here
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic("ids: no randomness: " + err.Error())
	}
	return prefix + "_" + encode(b)
}

// encode writes 128 bits as 26 base32 characters, the first carrying the
// top 3 bits.
func encode(b [16]byte) string {
	out := make([]byte, 26)
	// Read the 128 bits as hi:lo and take 5 bits at a time from the bottom.
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	for i := 25; i >= 0; i-- {
		out[i] = alphabet[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out)
}
