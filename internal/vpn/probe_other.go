//go:build !linux

package vpn

import "syscall"

// BindSocketToDevice reports that this platform cannot bind a socket to a
// device. The probe still runs: on these systems the routing table decides which
// interface a packet leaves by, which is enough to tell a carrying tunnel from a
// dead one — just not enough to prove the packet did not bypass it.
//
// The second return value is false so the caller can record that the probe was
// not device-pinned instead of presenting a weaker check as a strong one.
func BindSocketToDevice(string) (func(network, address string, c syscall.RawConn) error, bool) {
	return nil, false
}