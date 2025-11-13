package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"reflect"
)

type Dial func(net.Addr) (net.Conn, error)

func defaultDial(addr net.Addr) (net.Conn, error) {
	return net.Dial("tcp", addr.String())
}

type Redirection struct {
	Dial
	RedirectTo  net.Addr
	InboundConn net.Conn
}

type Redirector struct {
	ctx             context.Context
	redirectionChan chan *Redirection
}

func (r *Redirector) Redirect(redirection *Redirection) {
	select {
	case r.redirectionChan <- redirection:
		fmt.Println("redirect request")
	case <-r.ctx.Done():
		fmt.Println("exiting")
	}
}

func (r *Redirector) worker() {
	for {
		select {
		case redirection := <-r.redirectionChan:
			handle := func(redirection *Redirection) {
				if redirection.InboundConn == nil || reflect.ValueOf(redirection.InboundConn).IsNil() {
					fmt.Println("nil inbound conn")
					return
				}
				defer redirection.InboundConn.Close()
				if redirection.RedirectTo == nil || reflect.ValueOf(redirection.RedirectTo).IsNil() {
					fmt.Println("nil redirection addr")
					return
				}
				if redirection.Dial == nil {
					redirection.Dial = defaultDial
				}
				fmt.Println("redirecting connection from", redirection.InboundConn.RemoteAddr(), "to", redirection.RedirectTo.String())
				outboundConn, err := redirection.Dial(redirection.RedirectTo)
				if err != nil {
					fmt.Println("failed to redirect to target address", err)
					return
				}
				defer outboundConn.Close()
				errChan := make(chan error, 2)
				copyConn := func(a, b net.Conn) {
					_, err := io.Copy(a, b)
					errChan <- err
				}
				go copyConn(outboundConn, redirection.InboundConn)
				go copyConn(redirection.InboundConn, outboundConn)
				select {
				case err := <-errChan:
					if err != nil {
						fmt.Println("failed to redirect", err)
					}
					fmt.Println("redirection done")
				case <-r.ctx.Done():
					fmt.Println("exiting")
					return
				}
			}
			go handle(redirection)
		case <-r.ctx.Done():
			fmt.Println("shutting down redirector")
			return
		}
	}
}

func NewRedirector(ctx context.Context) *Redirector {
	r := &Redirector{
		ctx:             ctx,
		redirectionChan: make(chan *Redirection, 64),
	}
	go r.worker()
	return r
}
