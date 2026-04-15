package common

import (
	"strings"
	"testing"
)

func TestParseListenerSpecs_SingleWithAddr(t *testing.T) {
	got, err := ParseListenerSpecs("quic://:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Transport != "quic" || got[0].Addr != ":8080" {
		t.Errorf("got %+v, want {quic :8080}", got[0])
	}
}

func TestParseListenerSpecs_MultipleMixed(t *testing.T) {
	got, err := ParseListenerSpecs("quic://:8080;tls://127.0.0.1:9000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	want := []ListenerSpec{
		{Transport: "quic", Addr: ":8080"},
		{Transport: "tls", Addr: "127.0.0.1:9000"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseListenerSpecs_TrimsWhitespace(t *testing.T) {
	got, err := ParseListenerSpecs("  quic://:8080 ;  tls://127.0.0.1:9000  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].Transport != "quic" || got[1].Transport != "tls" {
		t.Errorf("got %+v", got)
	}
}

func TestParseListenerSpecs_SkipsEmptyEntries(t *testing.T) {
	got, err := ParseListenerSpecs("quic://:8080;;;tls://127.0.0.1:9000;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}

func TestParseListenerSpecs_IPv6BindAddr(t *testing.T) {
	// Everything after "://" is the raw addr; IPv6 literal survives intact.
	got, err := ParseListenerSpecs("tcp://[::1]:9000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Transport != "tcp" || got[0].Addr != "[::1]:9000" {
		t.Errorf("got %+v", got)
	}
}

func TestParseListenerSpecs_Errors(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantSub string
	}{
		{"empty input", "", "empty"},
		{"whitespace only", "   ", "empty"},
		{"separator only", ";;;", "no listener specs"},
		{"no separator", "tcp", "missing '://'"},
		{"colon only (no ://)", "tcp:127.0.0.1:9000", "missing '://'"},
		{"mixed with missing separator", "quic://:8080;udp", "missing '://'"},
		{"unsupported transport", "sctp://127.0.0.1:1", "unsupported transport"},
		{"missing transport", "://127.0.0.1:1", "missing transport"},
		{"duplicate transport", "quic://:8080;quic://127.0.0.1:9000", "duplicate transport"},
		{"empty addr after separator", "tcp://", "missing bind addr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseListenerSpecs(tc.in)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}
