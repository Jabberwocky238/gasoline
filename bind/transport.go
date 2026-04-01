package bind

import (
	"context"
	"net"
)

// TransportConn is the narrow connection surface shared by concrete transports.
type TransportConn interface {
	net.Conn
}

// TransportClient dials a remote transport endpoint and returns a single logical connection.
type TransportClient interface {
	Dial(ctx context.Context, address string) (TransportConn, error)
}

// TransportServer listens on a transport endpoint and accepts logical connections.
type TransportServer interface {
	Listen(address string) error
	Accept(ctx context.Context) (TransportConn, error)
	Close() error
	Addr() net.Addr
}
