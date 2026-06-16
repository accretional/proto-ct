package ctv2

import "fmt"

// base62Alphabet is ASCII-ascending (digits < upper < lower), so fixed-width
// zero-padded encodings would also sort lexically. It excludes '/','+','-','_',
// keeping encoded indices filesystem/URL-safe and the '-' filename separator
// unambiguous.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// encodeBase62 renders a non-negative int64 as a base-62 numeral (radix
// conversion, not byte encoding). Used to keep partition filenames compact.
func encodeBase62(n int64) string {
	if n <= 0 {
		return "0"
	}
	var buf [11]byte // max int64 needs 11 base-62 digits (62^11 > 2^63)
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = base62Alphabet[n%62]
		n /= 62
	}
	return string(buf[i:])
}

// decodeBase62 is the inverse of encodeBase62. Filenames are only hints (entries
// and the manifest carry authoritative indices), but a range-addressing tool may
// want to parse them back.
func decodeBase62(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty base62 string")
	}
	var n int64
	for _, c := range []byte(s) {
		var d int64
		switch {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case c >= 'A' && c <= 'Z':
			d = int64(c-'A') + 10
		case c >= 'a' && c <= 'z':
			d = int64(c-'a') + 36
		default:
			return 0, fmt.Errorf("invalid base62 digit %q", c)
		}
		n = n*62 + d
	}
	return n, nil
}
