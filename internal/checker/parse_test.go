package checker

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		input  string
		host   string
		port   int
		scheme string
	}{
		{"example.com", "example.com", 443, "https"},
		{"example.com:8443", "example.com", 8443, "https"},
		{"https://example.com:9443/path", "example.com", 9443, "https"},
		{"http://example.com:8080", "example.com", 8080, "http"},
		{"192.0.2.1:443", "192.0.2.1", 443, "https"},
		{"[2001:db8::1]:443", "2001:db8::1", 443, "https"},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.input, Options{})
		if err != nil {
			t.Fatalf("ParseTarget(%q): %v", tc.input, err)
		}
		if got.Host != tc.host || got.Port != tc.port || got.Scheme != tc.scheme {
			t.Fatalf("ParseTarget(%q) = host=%q port=%d scheme=%q", tc.input, got.Host, got.Port, got.Scheme)
		}
	}
}
