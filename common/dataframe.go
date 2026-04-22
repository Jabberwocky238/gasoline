package common

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	"github.com/jabberwocky238/gasoline/common/config"
)

// VXLAN-encapsulated data frame wire format (one UDP datagram = one frame):
//
//	[VXLAN header:8][inner Ethernet:14][inner IP packet:N]
//
// VXLAN header (RFC 7348):
//
//	bytes 0-3: flags — I bit (0x08) in byte 0 indicates VNI valid
//	bytes 4-6: VNI   — 24-bit Virtual Network Identifier
//	byte  7:   reserved
//
// Inner Ethernet:
//
//	bytes 0-5:   destination MAC (= dst VMAC)
//	bytes 6-11:  source MAC      (= src VMAC)
//	bytes 12-13: EtherType       (0x0800 IPv4 | 0x86DD IPv6)
//
// Forwarding decisions are keyed on (VNI, dst MAC) — the inner IP payload
// is never inspected by the data plane.
// MTU budget — dual stack.
//
// We allow different inner-IP sizes per address family so that L4 payload
// space stays close across stacks while the whole VXLAN-encapsulated frame
// still fits in a 1500-byte underlay:
//
//	Underlay MTU:              1500
//	- Outer Ethernet:            14
//	- Outer IP (IPv4):           20
//	- Outer UDP:                  8
//	- VXLAN header:               8
//	- Inner Ethernet:            14
//	─────────────────────────────────
//	- Available for inner IP:  1436
//
// Conservative per-family inner IP caps:
//
//	IPv4 packet (20B hdr): ≤ 1420  →  L4 payload ≤ 1400
//	IPv6 packet (40B hdr): ≤ 1400  →  L4 payload ≤ 1360
//
// The TUN device is configured with MTU = TunMTUv4 (1420); IPv6 senders
// must self-limit (or rely on PMTUD) to stay under TunMTUv6 (1400).

// MTUFor returns the per-family inner-IP cap.
func MTUFor(version int) int {
	switch version {
	case 4:
		return TunMTUv4
	case 6:
		return TunMTUv6
	}
	return 0
}

const (
	TunMTUv4 = 1420
	TunMTUv6 = 1400
	TunMTU   = TunMTUv4 // configured MTU for the TUN device (max inner IP size)

	EthHeaderSize   = 14
	VxlanHeaderSize = 8
	// VxlanOverhead = VXLAN header (8) + inner Ethernet (14).
	VxlanOverhead = VxlanHeaderSize + EthHeaderSize

	// MaxVxlanPayload is the maximum UDP datagram payload we will ever emit
	// on the inter-operator data plane (sized to the larger family cap).
	MaxVxlanPayload = 1500

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

// Buf exposes the full backing array so a recv path (e.g. port.Conn.ReadBatch)
// can write directly into it. After the kernel writes n bytes, call
// (or have the container call) commitSize(n).
func (f *DataFrame) Buf() []byte { return f.buf[:] }

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

// DstMAC returns the inner Ethernet destination MAC. Slices into the
// inner-Ethernet region of buf and delegates to the shared ethDstMAC
// helper (also used by ethernet.go's standalone parsers).
func (f *DataFrame) DstMAC() VMAC {
	if f.size < VxlanHeaderSize+6 {
		return VMAC{}
	}
	start := VxlanHeaderSize
	end := VxlanHeaderSize + 6
	return VMAC(f.buf[start:end])
}

// SrcMAC returns the inner Ethernet source MAC.
func (f *DataFrame) SrcMAC() VMAC {
	if f.size < VxlanHeaderSize+12 {
		return VMAC{}
	}
	start := VxlanHeaderSize + 6
	end := VxlanHeaderSize + 12
	return VMAC(f.buf[start:end])
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

// Reset clears the frame for reuse. Only size + Endpoint need zeroing —
// buf contents will be overwritten on the next Encode/Decode/recv.
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
	version := int(packet[0] >> 4)
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
const MaxBatchSize = 128

type DataFrameContainer struct {
	Frames [MaxBatchSize]*DataFrame
	bufs   [MaxBatchSize][]byte // bufs[i] aliases Frames[i].buf[:]
	Sizes  [MaxBatchSize]int
	Addrs  [MaxBatchSize]netip.AddrPort
	count  int

	Mu   sync.Mutex
	Drop bool
}

// Count returns the number of live frames in the batch.
func (c *DataFrameContainer) Count() int { return c.count }

// Full reports whether the batch has reached MaxBatchSize.
func (c *DataFrameContainer) Full() bool { return c.count >= MaxBatchSize }

// Live returns a slice view of the live frames ([0, count)).
// Consumers iterate this; do not append — capacity is MaxBatchSize.
func (c *DataFrameContainer) Live() []*DataFrame { return c.Frames[:c.count] }

// Reset clears per-batch state on the owned frames + count + Drop. The
// underlying DataFrame slots and bufs slab are kept (re-used next Get).
func (c *DataFrameContainer) Reset() {
	for i := 0; i < c.count; i++ {
		c.Frames[i].size = 0
	}
	c.count = 0
	c.Drop = false
}

// DefaultDataFrameContainerPool is the global batch-container pool.
// Initialised in init().
var DefaultDataFrameContainerPool *WaitPool

// GetDataFrameContainer takes one container from the pool. The container
// owns its own DataFrames across Get/Put cycles — caller must NOT release
// individual frames via PutFrame.
func GetDataFrameContainer() *DataFrameContainer {
	return DefaultDataFrameContainerPool.Get().(*DataFrameContainer)
}

// PutDataFrameContainer returns a container to the pool after Reset()
// (clears per-batch state on the owned frames, keeps the slot array).
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

const (
	SessionIDLen    = 16
	OperatorUUIDLen = 16
	VMACLen         = config.VMACLen
)

type VMAC = config.VMAC
type VNI = config.VNI

const VNIMax = config.VNIMax

var EthBroadcastMAC = config.EthBroadcastMAC

func ParseVNI(s string) (VNI, error)  { return config.ParseVNI(s) }
func VNIFromBytes3(b [3]byte) VNI     { return config.VNIFromBytes3(b) }
