package datacom

import (
	"net/netip"
	"testing"
)

func TestServerListRoundTrip(t *testing.T) {
	in := ServerList{
		{
			UUID:  [16]byte{0xA0, 1, 2, 3},
			Host:  netip.MustParseAddr("1.2.3.4"),
			Ports: []PortRange{{20000, 20063}, {30000, 30015}},
		},
		{
			UUID:  [16]byte{0xB0},
			Host:  netip.MustParseAddr("2001:db8::1"),
			Ports: []PortRange{{40000, 40000}},
		},
	}
	out, err := unmarshalServerList(marshalServerList(in))
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("count: got %d want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].UUID != in[i].UUID {
			t.Errorf("[%d] uuid mismatch", i)
		}
		if out[i].Host != in[i].Host {
			t.Errorf("[%d] host: got %s want %s", i, out[i].Host, in[i].Host)
		}
		if len(out[i].Ports) != len(in[i].Ports) {
			t.Fatalf("[%d] port count: got %d want %d", i, len(out[i].Ports), len(in[i].Ports))
		}
		for j := range in[i].Ports {
			if out[i].Ports[j] != in[i].Ports[j] {
				t.Errorf("[%d][%d] port: got %v want %v", i, j, out[i].Ports[j], in[i].Ports[j])
			}
		}
	}
}

func TestServerListEmpty(t *testing.T) {
	out, err := unmarshalServerList(marshalServerList(nil))
	if err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if out != nil {
		t.Fatalf("expected nil, got %v", out)
	}
	// A truly empty byte slice must also decode cleanly.
	if _, err := unmarshalServerList(nil); err != nil {
		t.Fatalf("unmarshal nil bytes: %v", err)
	}
}
