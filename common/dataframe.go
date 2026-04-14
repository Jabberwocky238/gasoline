package common

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// VXLAN-encapsulated data frame wire format (one UDP datagram = one frame):
//
//   [VXLAN header:8][inner Ethernet:14][inner IP packet:N]
//
// VXLAN header (RFC 7348):
//   bytes 0-3: flags — I bit (0x08) in byte 0 indicates VNI valid
//   bytes 4-6: VNI   — 24-bit Virtual Network Identifier
//   byte  7:   reserved
//
// Inner Ethernet:
//   bytes 0-5:   destination MAC (= dst VMAC)
//   bytes 6-11:  source MAC      (= src VMAC)
//   bytes 12-13: EtherType       (0x0800 IPv4 | 0x86DD IPv6)
//
// Forwarding decisions are keyed on (VNI, dst MAC) — the inner IP payload
// is never inspected by the data plane.

const (
	VxlanHeaderSize = 8
	EthHeaderSize   = 14

	vxlanFlagsValid = 0x08 // I bit — VNI present

	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
)

// DataFrame is a pooled, reusable VXLAN frame buffer.
//
// The struct exposes only buf + size; all wire-level fields (VNI, MACs,
// EtherType, inner packet) are computed on demand via methods that slice
// directly into buf — zero per-packet allocation, zero pre-extraction.
//
// Usage:
//
//	df := common.GetFrame()
//	df.EncodeFrame(vni, ethFrame)            // writes to buf, sets size
//	wire := df.Bytes()                       // raw VXLAN datagram
//	... or after Decode:
//	df.Decode(wire)
//	df.VNI(); df.SrcMAC(); df.DstMAC(); df.Packet(); df.Frame()
type DataFrame struct {
	buf  [MaxPacketSize]byte
	size int
}

// --------------- Lazy accessors (slice into buf) ---------------

// Size returns the total wire size of the frame.
func (f *DataFrame) Size() int { return f.size }

// Bytes returns the full wire datagram (VXLAN + Ethernet + payload).
func (f *DataFrame) Bytes() []byte { return f.buf[:f.size] }

// VNI returns the 24-bit VXLAN Network Identifier from the header.
func (f *DataFrame) VNI() VNI {
	if f.size < VxlanHeaderSize {
		return 0
	}
	return VNIFromBytes3([3]byte{f.buf[4], f.buf[5], f.buf[6]})
}

// DstMAC returns the inner Ethernet destination MAC.
func (f *DataFrame) DstMAC() VMAC {
	var m VMAC
	if f.size >= VxlanHeaderSize+6 {
		copy(m[:], f.buf[VxlanHeaderSize:VxlanHeaderSize+6])
	}
	return m
}

// SrcMAC returns the inner Ethernet source MAC.
func (f *DataFrame) SrcMAC() VMAC {
	var m VMAC
	if f.size >= VxlanHeaderSize+12 {
		copy(m[:], f.buf[VxlanHeaderSize+6:VxlanHeaderSize+12])
	}
	return m
}

// EtherType returns the inner Ethernet EtherType (0x0800 / 0x86DD).
func (f *DataFrame) EtherType() uint16 {
	if f.size < VxlanHeaderSize+EthHeaderSize {
		return 0
	}
	return binary.BigEndian.Uint16(f.buf[VxlanHeaderSize+12 : VxlanHeaderSize+14])
}

// Frame returns the inner Ethernet frame (Eth header + payload).
func (f *DataFrame) Frame() []byte {
	if f.size < VxlanHeaderSize+EthHeaderSize {
		return nil
	}
	return f.buf[VxlanHeaderSize:f.size]
}

// Packet returns the inner IP packet (after stripping the inner Eth header).
func (f *DataFrame) Packet() []byte {
	if f.size < VxlanHeaderSize+EthHeaderSize {
		return nil
	}
	return f.buf[VxlanHeaderSize+EthHeaderSize : f.size]
}

// Reset clears the frame for reuse. Only size needs zeroing — buf contents
// will be overwritten on the next Encode/Decode.
func (f *DataFrame) Reset() {
	f.size = 0
}

// --------------- Encoders ---------------

// EncodeFrame prepends an 8-byte VXLAN header to a pre-built Ethernet
// frame and stores it in the internal buffer. Returns the wire bytes.
//
// ethFrame layout: [dstMAC:6][srcMAC:6][ethType:2][payload...]
func (f *DataFrame) EncodeFrame(vni VNI, ethFrame []byte) []byte {
	if len(ethFrame) < EthHeaderSize {
		panic(fmt.Sprintf("dataframe: eth frame too short %d", len(ethFrame)))
	}
	if len(ethFrame) > MaxVxlanPayload {
		panic(fmt.Sprintf("dataframe: eth frame %d > MaxVxlanPayload %d", len(ethFrame), MaxVxlanPayload))
	}

	// VXLAN header
	f.buf[0] = vxlanFlagsValid
	f.buf[1] = 0
	f.buf[2] = 0
	f.buf[3] = 0
	vb := vni.Bytes3()
	f.buf[4] = vb[0]
	f.buf[5] = vb[1]
	f.buf[6] = vb[2]
	f.buf[7] = 0

	// Inner Ethernet + payload — verbatim from caller.
	copy(f.buf[VxlanHeaderSize:], ethFrame)

	f.size = VxlanHeaderSize + len(ethFrame)
	return f.buf[:f.size]
}

// Encode (legacy) constructs an Ethernet frame from (srcMAC, dstMAC, ipPacket)
// then VXLAN-wraps it. New code should build the Eth frame upstream and
// call EncodeFrame.
func (f *DataFrame) Encode(vni VNI, srcVMAC, dstVMAC VMAC, packet []byte) []byte {
	version := InnerIPVersion(packet)
	mtu := MTUFor(version)
	if mtu == 0 {
		panic(fmt.Sprintf("dataframe: unknown IP version for packet[0]=0x%02x", packet[0]))
	}
	if len(packet) > mtu {
		panic(fmt.Sprintf("dataframe: inner IPv%d packet %d > mtu %d", version, len(packet), mtu))
	}
	ethType := EtherTypeIPv4
	if version == 6 {
		ethType = EtherTypeIPv6
	}
	tmpBuf := GetBuffer()
	defer PutBuffer(tmpBuf)
	tmp := (*tmpBuf)[:EthHeaderSize+len(packet)]
	WriteEthHeader(tmp, dstVMAC, srcVMAC, uint16(ethType))
	copy(tmp[EthHeaderSize:], packet)
	return f.EncodeFrame(vni, tmp)
}

// --------------- Decoder ---------------

// Decode validates a received VXLAN-encapsulated datagram and stores it.
// The wire-level fields are NOT pre-extracted — call VNI(), DstMAC(), etc.
// on demand. data is copied into the internal buffer.
func (f *DataFrame) Decode(data []byte) error {
	if len(data) < VxlanHeaderSize+EthHeaderSize {
		return fmt.Errorf("vxlan frame too short: %d", len(data))
	}
	if len(data) > MaxVxlanPayload {
		return fmt.Errorf("vxlan frame too large: %d > %d", len(data), MaxVxlanPayload)
	}
	f.size = len(data)
	copy(f.buf[:f.size], data)

	if f.buf[0]&vxlanFlagsValid == 0 {
		return fmt.Errorf("vxlan: I flag not set")
	}
	return nil
}

// --------------- DataFrame pool ---------------

// DefaultFramePool is the global VXLAN DataFrame pool. Initialised in init().
var DefaultFramePool *WaitPool

// GetFrame retrieves a DataFrame from the global pool.
func GetFrame() *DataFrame {
	return DefaultFramePool.Get().(*DataFrame)
}

// PutFrame returns a DataFrame to the global pool after resetting it.
func PutFrame(f *DataFrame) {
	f.Reset()
	DefaultFramePool.Put(f)
}

// --------------- DataFrameContainer + pool ---------------

// MaxBatchSize caps the number of frames in one DataFrameContainer.
// Matches OVS's NETDEV_MAX_BURST — each batch is one unit of work
// passed between pipeline stages (RX → decode → Forward → TX).
const MaxBatchSize = 32

// DataFrameContainer aggregates a batch of *DataFrame pointers along with
// per-batch context. The container is empty on Get — frames come from the
// DataFrame pool via GetFrame() and are Push-ed in; on Put the container
// releases each frame back to the frame pool before it returns itself to
// the container pool.
//
// Design: OVS dp_packet_batch + WireGuard Queue*Container.  Each pipeline
// stage operates on a whole container — the channel/mutex cost of passing
// the container is amortised across up to MaxBatchSize frames.
//
// Fields:
//
//	frames   : slot array of borrowed *DataFrame pointers (nil when empty)
//	count    : number of live frames (0 ≤ count ≤ MaxBatchSize)
//	Endpoint : per-batch UDP endpoint (source on RX, destination on TX)
//	Mu       : container-wide mutex for cross-stage synchronisation
//	Drop     : true if any stage marks the batch as undeliverable
type DataFrameContainer struct {
	frames   [MaxBatchSize]*DataFrame
	count    int
	Endpoint *net.UDPAddr
	Mu       sync.Mutex
	Drop     bool
}

// Count returns the number of live frames in the batch.
func (c *DataFrameContainer) Count() int { return c.count }

// Full reports whether the batch has reached MaxBatchSize.
func (c *DataFrameContainer) Full() bool { return c.count >= MaxBatchSize }

// Push appends f to the batch. Returns false if the batch is already full.
// The container takes ownership of f — do not call PutFrame on it yourself;
// it will be released when the container is Put back.
func (c *DataFrameContainer) Push(f *DataFrame) bool {
	if c.count >= MaxBatchSize {
		return false
	}
	c.frames[c.count] = f
	c.count++
	return true
}

// Frames returns a slice view of the live frames ([0, count)).
// Consumers iterate this; do not append — capacity is MaxBatchSize.
func (c *DataFrameContainer) Frames() []*DataFrame { return c.frames[:c.count] }

// Reset releases each live frame back to the DataFrame pool, nils all
// slots, and clears per-batch metadata. Called automatically by
// PutDataFrameContainer.
func (c *DataFrameContainer) Reset() {
	for i := 0; i < c.count; i++ {
		PutFrame(c.frames[i])
		c.frames[i] = nil
	}
	c.count = 0
	c.Endpoint = nil
	c.Drop = false
}

// DefaultDataFrameContainerPool is the global batch-container pool.
// Initialised in init(). A fresh container has all slots nil and count=0.
var DefaultDataFrameContainerPool *WaitPool

// GetDataFrameContainer takes one empty container from the pool.
// Fill it via Push(); release via PutDataFrameContainer.
func GetDataFrameContainer() *DataFrameContainer {
	return DefaultDataFrameContainerPool.Get().(*DataFrameContainer)
}

// PutDataFrameContainer returns a container to the pool after Reset()
// (which releases each live frame back to the DataFrame pool).
func PutDataFrameContainer(c *DataFrameContainer) {
	c.Reset()
	DefaultDataFrameContainerPool.Put(c)
}

// init wires up both pools at package load time. Both default to unbounded
// (max=0); for backpressure replace the variables before any Get* call.
func init() {
	DefaultFramePool = NewWaitPool(0, func() any {
		return new(DataFrame)
	})
	DefaultDataFrameContainerPool = NewWaitPool(0, func() any {
		return &DataFrameContainer{}
	})
}
