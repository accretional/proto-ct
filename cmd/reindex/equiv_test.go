package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	ippb "github.com/accretional/proto-ip/proto/ippb"
)

// TestKey16MatchesProtoIPEncoding pins R0's "same bytes everywhere" contract:
// the 16-byte BLOB key used by this reverse index must be byte-identical to
// proto-ip's ip.IP message (two big-endian sint64 halves of the ::ffff:0:0/96
// mapped As16 form). This replicates proto-ip's encode/decode (see
// proto-ip geoip/geofeed.go:177 protoFromAddr and the symmetric decoders in
// localip/list.go, rdap/client.go, geoip/server.go) and asserts a round trip
// through the actual ippb.IP type lands on the same bytes key16 produces.
//
// NOTE: proto-ip's protoFromAddr is unexported, so this test mirrors its logic
// rather than calling it. A shared exported helper would let all repos share
// one implementation instead of these parallel copies.
func TestKey16MatchesProtoIPEncoding(t *testing.T) {
	cases := []string{
		"1.2.3.4",
		"203.0.113.7",
		"0.0.0.0",
		"255.255.255.255",
		"::1",
		"2001:db8::1",
		"2600:1f18:dead:beef::1", // high bit set -> negative interface half
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	}
	for _, s := range cases {
		addr := netip.MustParseAddr(s)
		k, _, ok := key16(s)
		if !ok {
			t.Fatalf("key16(%s) failed", s)
		}

		// Encode exactly as proto-ip does.
		a := addr.As16()
		msg := &ippb.IP{
			NetworkPrefix:       int64(binary.BigEndian.Uint64(a[0:8])),
			InterfaceIdentifier: int64(binary.BigEndian.Uint64(a[8:16])),
		}

		// Decode the proto halves back to 16 bytes as proto-ip's consumers do.
		var buf [16]byte
		binary.BigEndian.PutUint64(buf[0:8], uint64(msg.GetNetworkPrefix()))
		binary.BigEndian.PutUint64(buf[8:16], uint64(msg.GetInterfaceIdentifier()))

		if !bytes.Equal(k, buf[:]) {
			t.Errorf("%s: key16=%x != proto-ip round-trip=%x", s, k, buf)
		}
	}
}
