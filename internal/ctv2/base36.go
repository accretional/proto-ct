package ctv2

import "fmt"

// base36Alphabet is single-case (digits + lowercase) so encoded indices are safe
// on case-INSENSITIVE filesystems (e.g. macOS APFS, the common archive volume) —
// a two-case base-62 scheme would fold "DYB" and "DYb" onto the same filename and
// collide. It excludes '/','+','-','_', so names stay filesystem/URL-safe and the
// '-' filename separator is unambiguous. The alphabet is ASCII-ascending, so a
// fixed-width zero-padded encoding would also sort lexically.
const base36Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

// encodeBase36 renders a non-negative int64 as a base-36 numeral (radix
// conversion, not byte encoding). Used to keep partition filenames compact.
func encodeBase36(n int64) string {
	if n <= 0 {
		return "0"
	}
	var buf [13]byte // max int64 needs 13 base-36 digits (36^13 > 2^63)
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = base36Alphabet[n%36]
		n /= 36
	}
	return string(buf[i:])
}

// decodeBase36 is the inverse of encodeBase36. Filenames are only hints (entries
// and the manifest carry authoritative indices), but a range-addressing tool may
// want to parse them back.
func decodeBase36(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty base36 string")
	}
	var n int64
	for _, c := range []byte(s) {
		var d int64
		switch {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'a' && c <= 'z':
			d = int64(c-'a') + 10
		default:
			return 0, fmt.Errorf("invalid base36 digit %q", c)
		}
		n = n*36 + d
	}
	return n, nil
}
