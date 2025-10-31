package transport

import "net"

type TransportServer interface {
	Listen(host string, port int) error
	Accept() (TransportConn, error)
	Close() error
}

type TransportClient interface {
	Dial(endpoint string) (TransportConn, error)
}

type TransportConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
}

// for example, there is an overlap among the layers:
// [device] -> trojan -> tcp -> [device]
// [device] -> shadowsocks -> trojan -> hysteria2 -> udp -> [device]

/// when the device writes data to the 1st layer, it should encrypt the data and write it to the 2nd layer
// here is an issue about handshake:
// like we have trojan and tcp, when connecting, trojan need to handshake, but the outlet is tcp
// [device] -x-> trojan -> tcp -> [device]
// the trojan send handshake to tcp, waiting for tcp to respond.
// so the tcp layer will be started before the trojan layer, then the trojan could handshake.
// which means, if the upper layer handshake failed, the lower layer should not be started.

// for the server side, Start() will bind a port and listen for incoming connections.
// for the client side, Start() will connect to the server and start the handshake.
// each kind of layer should have a server and a client.
