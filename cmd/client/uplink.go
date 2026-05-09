package client

import (
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/jabberwocky238/gasoline/common"
	"github.com/jabberwocky238/gasoline/device/vtep"
	"github.com/jabberwocky238/gasoline/transport"
)

// uplink adapts a transport.Conn to vtep.Port. From the vtep's
// perspective the encrypted client↔operator tunnel is just one L2
// attachment named "uplink": one egress (SendFrame → conn.WritePacket)
// and one ingress goroutine (conn.ReadPacket → vtep.DeliverL2).
//
// Keepalive frames are NOT propagated to vtep — they are intercepted
// here and dispatched to onKeepaliveReply, keeping vtep unaware of the
// transport-layer liveness protocol.
type uplink struct {
	ctx  *common.GasolineGeneralContext
	conn transport.Conn
	vtep *vtep.Device

	selfMAC          common.VMAC
	onKeepaliveReply func()

	closed atomic.Bool
}

const uplinkPortID = "uplink"

func newUplink(parent *common.GasolineGeneralContext, conn transport.Conn, v *vtep.Device, selfMAC common.VMAC, onKA func()) *uplink {
	return &uplink{
		ctx:              parent.Child(log.Fields{"component": "uplink"}),
		conn:             conn,
		vtep:             v,
		selfMAC:          selfMAC,
		onKeepaliveReply: onKA,
	}
}

// --------------- vtep.Port ---------------

func (u *uplink) ID() string { return uplinkPortID }

// SendFrame ignores dstMAC — the transport.Conn is a single peer pipe;
// every frame goes to the same operator regardless of inner MAC.
func (u *uplink) SendFrame(_ common.VMAC, frame []byte) error {
	if u.closed.Load() {
		return nil
	}
	return u.conn.WritePacket(frame)
}

// --------------- ingress ---------------

// Start spawns the rxLoop reading from the transport and feeding vtep.
func (u *uplink) Start() { go u.rxLoop() }

// Close stops the rxLoop. The transport.Conn is not closed here —
// ownership stays with the Client.
func (u *uplink) Close() error {
	if !u.closed.CompareAndSwap(false, true) {
		return nil
	}
	u.ctx.Cancel()
	return nil
}

func (u *uplink) rxLoop() {
	bufp := common.GetBuffer()
	defer common.PutBuffer(bufp)
	buf := *bufp
	for {
		select {
		case <-u.ctx.Done():
			return
		default:
		}
		n, err := u.conn.ReadPacket(buf)
		if err != nil {
			if u.closed.Load() {
				return
			}
			u.ctx.Logger().Debugf("conn read: %v", err)
			return
		}
		if n < common.EthHeaderSize {
			continue
		}
		frame := buf[:n]

		// Intercept keepalive replies before vtep ever sees them.
		if common.IsKeepaliveReply(frame, u.selfMAC) {
			if u.onKeepaliveReply != nil {
				u.onKeepaliveReply()
			}
			continue
		}

		if err := u.vtep.DeliverL2(uplinkPortID, frame, nil); err != nil {
			u.ctx.Logger().Debugf("deliver L2: %v", err)
		}
	}
}
