package common

type Conn interface {
	Write(Packet) error
	Read() (Packet, error)
	Metadata() *Metadata
	Close() error
}

type Tunnel interface {
	// HandleConn will handle a connection (tcp or udp) blocking
	HandleConn(conn Conn, metadata *Metadata)
	// // NatTable return nat table
	// NatTable() NatTable
}
