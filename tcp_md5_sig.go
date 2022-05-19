//go:build !linux
// +build !linux

package corebgp

import (
	"errors"
	"net"
)

// SetTCPMD5Signature sets a tcp md5 signature on a socket for the provided
// address, prefix length, and key. This function is only supported on Linux. To
// unset a signature provide an empty key. Prefix length is ignored on kernels
// < 4.13.
//
// https://tools.ietf.org/html/rfc2385
func SetTCPMD5Signature(fd int, address net.IP, prefixLen uint8,
	key string) error {
	return errors.New("unsupported")
}
