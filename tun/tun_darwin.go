//go:build darwin

package tun

import "golang.org/x/sys/unix"

const packetOffset = 4

func (t *Tun) Read(buf []byte) (int, error) {
	tmp := make([]byte, len(buf)+packetOffset)
	n, err := t.tunIf.Read(tmp)
	if err != nil {
		return 0, err
	}
	if n <= packetOffset {
		return 0, nil
	}
	copy(buf, tmp[packetOffset:n])
	return n - packetOffset, nil
}

func (t *Tun) Write(buf []byte) (int, error) {
	var hdr [packetOffset]byte
	if len(buf) > 0 && (buf[0]>>4) == 6 {
		hdr[3] = byte(unix.AF_INET6)
	} else {
		hdr[3] = byte(unix.AF_INET)
	}
	tmp := make([]byte, packetOffset+len(buf))
	copy(tmp, hdr[:])
	copy(tmp[packetOffset:], buf)
	n, err := t.tunIf.Write(tmp)
	if err != nil {
		return 0, err
	}
	if n <= packetOffset {
		return 0, nil
	}
	return n - packetOffset, nil
}
