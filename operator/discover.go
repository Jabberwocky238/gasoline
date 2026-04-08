package operator

import (
	"encoding/binary"
	"fmt"

	log "github.com/sirupsen/logrus"
)

// discoverEntry represents one operator in a discover response.
// Wire: [uuid:16][addrLen:2][addr:N]
type discoverEntry struct {
	UUID OperatorUUIDType
	Addr string
}

func encodeDiscoverResp(entries []discoverEntry) []byte {
	// [count:2][entries...]
	size := 2
	for _, e := range entries {
		size += 16 + 2 + len(e.Addr)
	}
	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(entries)))
	offset := 2
	for _, e := range entries {
		copy(buf[offset:offset+16], e.UUID[:])
		offset += 16
		binary.BigEndian.PutUint16(buf[offset:offset+2], uint16(len(e.Addr)))
		offset += 2
		copy(buf[offset:offset+len(e.Addr)], e.Addr)
		offset += len(e.Addr)
	}
	return buf
}

func decodeDiscoverResp(data []byte) ([]discoverEntry, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("discover resp too short")
	}
	count := int(binary.BigEndian.Uint16(data[0:2]))
	offset := 2
	entries := make([]discoverEntry, 0, count)
	for i := 0; i < count; i++ {
		if offset+16+2 > len(data) {
			return nil, fmt.Errorf("discover resp truncated at entry %d", i)
		}
		var e discoverEntry
		copy(e.UUID[:], data[offset:offset+16])
		offset += 16
		addrLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+addrLen > len(data) {
			return nil, fmt.Errorf("discover resp truncated at entry %d addr", i)
		}
		e.Addr = string(data[offset : offset+addrLen])
		offset += addrLen
		entries = append(entries, e)
	}
	return entries, nil
}

// handleDiscoverReq responds with the list of known operators (from Registry).
func (o *Operator) handleDiscoverReq(peer *OperatorPeer) {
	var entries []discoverEntry

	// Add self
	entries = append(entries, discoverEntry{
		UUID: o.uuid,
		Addr: o.cfg.OpExternalAddr,
	})

	// Add all known operators from Registry
	o.Registry.opMu.RLock()
	for uuid, entry := range o.Registry.OperatorMap {
		entries = append(entries, discoverEntry{UUID: uuid, Addr: entry.Addr})
	}
	o.Registry.opMu.RUnlock()

	peer.SendControl(CtrlDiscoverResp, encodeDiscoverResp(entries))
}

// handleDiscoverResp processes a discover response and connects to unknown operators.
func (o *Operator) handleDiscoverResp(payload []byte) {
	entries, err := decodeDiscoverResp(payload)
	if err != nil {
		log.Debugf("Bad discover resp: %v", err)
		return
	}

	for _, e := range entries {
		// Skip self
		if e.UUID == o.uuid {
			continue
		}
		// Skip already connected
		if _, ok := o.operators.Get(e.UUID); ok {
			continue
		}

		log.Infof("Discovered operator %x at %s, connecting...", e.UUID, e.Addr)
		go func(addr string) {
			if err := o.DialOperator(addr); err != nil {
				log.Errorf("Discover dial %s: %v", addr, err)
			}
		}(e.Addr)
	}
}

// Bootstrap connects to seed operators and discovers the cluster.
func (o *Operator) Bootstrap() {
	for _, addr := range o.cfg.DiscoverAddrs {
		if addr == "" {
			continue
		}
		log.Infof("Bootstrapping from seed %s", addr)
		if err := o.DialOperator(addr); err != nil {
			log.Errorf("Bootstrap dial %s: %v", addr, err)
			continue
		}
	}

	// After connecting to seeds, request their operator lists
	o.operators.mu.RLock()
	peers := make([]*OperatorPeer, 0, len(o.operators.peers))
	for _, p := range o.operators.peers {
		peers = append(peers, p)
	}
	o.operators.mu.RUnlock()

	for _, peer := range peers {
		peer.SendControl(CtrlDiscoverReq, nil)
	}
}
