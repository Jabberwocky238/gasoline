//go:build !darwin

package tun

func (t *Tun) Read(buf []byte) (int, error) {
	return t.tunIf.Read(buf)
}

func (t *Tun) Write(buf []byte) (int, error) {
	return t.tunIf.Write(buf)
}
