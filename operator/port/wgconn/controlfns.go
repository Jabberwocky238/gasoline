/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"net"
	"syscall"
)

// UDP socket read/write buffer size (32MB). Linux clamps to
// net.core.{r,w}mem_max unless the process holds CAP_NET_ADMIN, in which
// case _linux.go falls back to SO_*BUFFORCE which ignores the cap. macOS
// caps at 7 MB by default (kern.ipc.maxsockbuf / 2). Windows is happy
// with anything up to ~16 MB on modern builds.
//
// To get the full 32MB on Linux without root:
//
//	sudo sysctl -w net.core.rmem_max=33554432 net.core.wmem_max=33554432
//	sudo sysctl -w net.core.rmem_default=33554432 net.core.wmem_default=33554432
//
// Persist by adding to /etc/sysctl.d/99-gasoline.conf.
const socketBufferSize = 32 << 20

// controlFn is the callback function signature from net.ListenConfig.Control.
// It is used to apply platform specific configuration to the socket prior to
// bind.
type controlFn func(network, address string, c syscall.RawConn) error

// controlFns is a list of functions that are called from the listen config
// that can apply socket options.
var controlFns = []controlFn{}

// listenConfig returns a net.ListenConfig that applies the controlFns to the
// socket prior to bind. This is used to apply socket buffer sizing and packet
// information OOB configuration for sticky sockets.
func listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			for _, fn := range controlFns {
				if err := fn(network, address, c); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
