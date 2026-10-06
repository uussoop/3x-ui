//go:build linux

package vpn

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// BindSocketToDevice returns a net.Dialer Control hook that pins the socket to a
// network device via SO_BINDTODEVICE, plus whether this platform can do it.
//
// Binding rather than routing matters for a probe: routing alone lets the kernel
// satisfy the probe over the real uplink, so a tunnel that is up but not carrying
// traffic (or carrying only IPv4 while IPv6 escapes) would still look healthy.
func BindSocketToDevice(device string) (func(network, address string, c syscall.RawConn) error, bool) {
	return func(_, _ string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) {
			setErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
		})
		if err != nil {
			return err
		}
		return setErr
	}, true
}