package trojan

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"net"

	"github.com/sirupsen/logrus"
	"wwww/transport/trojan/common"
)

type _PacketConn struct {
	Conn
}

func (c *_PacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	return c.ReadWithMetadata(payload)
}

func (c *_PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	address, err := NewAddressFromAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	m := &Metadata{
		Address: address,
	}
	return c.WriteWithMetadata(payload, m)
}

func (c *_PacketConn) WriteWithMetadata(payload []byte, metadata *Metadata) (int, error) {
	packet := make([]byte, 0, MaxPacketSize)
	w := bytes.NewBuffer(packet)
	metadata.Address.WriteTo(w)

	length := len(payload)
	lengthBuf := [2]byte{}
	crlf := [2]byte{0x0d, 0x0a}

	binary.BigEndian.PutUint16(lengthBuf[:], uint16(length))
	w.Write(lengthBuf[:])
	w.Write(crlf[:])
	w.Write(payload)

	_, err := c.Conn.Write(w.Bytes())

	logrus.Debug("udp packet remote", c.RemoteAddr(), "metadata", metadata, "size", length)
	return len(payload), err
}

func (c *_PacketConn) ReadWithMetadata(payload []byte) (int, *Metadata, error) {
	addr := &Address{
		NetworkType: "udp",
	}
	if err := addr.ReadFrom(c.Conn); err != nil {
		return 0, nil, common.NewError("failed to parse udp packet addr").Base(err)
	}
	lengthBuf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, lengthBuf[:]); err != nil {
		return 0, nil, common.NewError("failed to read length")
	}
	length := int(binary.BigEndian.Uint16(lengthBuf[:]))

	crlf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, crlf[:]); err != nil {
		return 0, nil, common.NewError("failed to read crlf")
	}

	if len(payload) < length || length > MaxPacketSize {
		io.CopyN(ioutil.Discard, c.Conn, int64(length)) // drain the rest of the packet
		return 0, nil, common.NewError("incoming packet size is too large")
	}

	if _, err := io.ReadFull(c.Conn, payload[:length]); err != nil {
		return 0, nil, common.NewError("failed to read payload")
	}

	logrus.Debug("udp packet from", c.RemoteAddr(), "metadata", addr.String(), "size", length)
	return length, &Metadata{
		Address: addr,
	}, nil
}
