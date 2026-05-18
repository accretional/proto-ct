package main

import (
	"os"
	"testing"
)

func TestShardKey(t *testing.T) {
	cases := []struct {
		domain, wantTLD, wantBucket string
	}{
		{"www.example.com", "com", "e"},
		{"api.amazon.com", "com", "a"},
		{"subdomain.123start.com", "com", "0"},
		{"example.net", "net", "exports"},
		{"foo.co.uk", "co.uk", "exports"},
		{"s3.amazonaws.com.cn", "com.cn", "exports"},
		{"notadomain", "_other", "exports"},
	}
	for _, c := range cases {
		tld, bucket := shardKey(c.domain)
		if tld != c.wantTLD || bucket != c.wantBucket {
			t.Errorf("shardKey(%q) = (%q, %q), want (%q, %q)",
				c.domain, tld, bucket, c.wantTLD, c.wantBucket)
		}
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"example.com", "example.com"},
		{"  Example.COM  ", "example.com"},
		{"sub.example.com", "sub.example.com"},
		{"*.example.com", ""},            // wildcard — caller must strip before calling
		{"example", ""},                  // no dot
		{".example.com", ""},             // leading dot
		{"example.com.", ""},             // trailing dot
		{"exa mple.com", ""},             // space
		{"ex@mple.com", ""},              // invalid char
		{"my-host.example.com", "my-host.example.com"},
	}
	for _, c := range cases {
		got := normalize(c.input)
		if got != c.want {
			t.Errorf("normalize(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestPackedCounts(t *testing.T) {
	m := make(map[string]uint64)
	addDirect(m, "a.com")
	addDirect(m, "a.com")
	addWildcard(m, "a.com")

	v := m["a.com"]
	if directCount(v) != 2 {
		t.Errorf("directCount = %d, want 2", directCount(v))
	}
	if wildcardCount(v) != 1 {
		t.Errorf("wildcardCount = %d, want 1", wildcardCount(v))
	}
}

func TestKMergeRoundtrip(t *testing.T) {
	tmp := t.TempDir()

	chunk1 := tmp + "/c1.tsv"
	chunk2 := tmp + "/c2.tsv"

	// chunk1: a.com direct=3 wild=0, b.com direct=1 wild=2
	os.WriteFile(chunk1, []byte("a.com\t3\t0\nb.com\t1\t2\n"), 0o644)
	// chunk2: a.com direct=1 wild=1, c.com direct=0 wild=5
	os.WriteFile(chunk2, []byte("a.com\t1\t1\nc.com\t0\t5\n"), 0o644)

	type result struct{ direct, wildcard uint32 }
	got := map[string]result{}
	err := kMerge([]string{chunk1, chunk2}, func(domain string, direct, wildcard uint32) error {
		got[domain] = result{direct, wildcard}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]result{
		"a.com": {4, 1},
		"b.com": {1, 2},
		"c.com": {0, 5},
	}
	for domain, w := range want {
		g, ok := got[domain]
		if !ok {
			t.Errorf("missing domain %q", domain)
			continue
		}
		if g != w {
			t.Errorf("%q: got {%d,%d}, want {%d,%d}", domain, g.direct, g.wildcard, w.direct, w.wildcard)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d domains, want %d", len(got), len(want))
	}
}
