package corebgp

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// https://github.com/torvalds/linux/blob/v5.11-rc7/include/uapi/linux/tcp.h#L326
type tcpMD5Sig struct {
	ssFamily  uint16 // https://github.com/torvalds/linux/blob/v5.11-rc7/include/uapi/linux/socket.h#L16
	ss        [126]byte
	flags     uint8
	prefixLen uint8
	keyLen    uint16
	ifIndex   uint32 // nolint: structcheck
	key       [80]byte
}

func newTCPMD5Sig(fd int, address net.IP, prefixLen uint8, key string) (
	tcpMD5Sig, error) {
	t := tcpMD5Sig{
		flags: unix.TCP_MD5SIG_FLAG_PREFIX,
	}
	if len(key) > unix.TCP_MD5SIG_MAXKEYLEN {
		return t, fmt.Errorf("md5 key len is > %d",
			unix.TCP_MD5SIG_MAXKEYLEN)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return t, err
	}
	switch sa.(type) {
	case *unix.SockaddrInet4:
		if address.To4() == nil {
			// we can only set a key for an ipv4 addr on an af_inet socket
			return t, errors.New("invalid address")
		}
		t.ssFamily = unix.AF_INET
		copy(t.ss[2:], address.To4())
	case *unix.SockaddrInet6:
		t.ssFamily = unix.AF_INET6
		if address.To4() == nil && address.To16() == nil {
			// https://github.com/torvalds/linux/blob/v5.11-rc7/net/ipv6/tcp_ipv6.c#L636-L640
			//
			// address may be ipv4 or ipv6 for an AF_INET6 wildcard socket.
			return t, errors.New("invalid address")
		}
		// ensure address is represented as 16 bytes as ipv4-mapped ipv6 is
		// valid here
		copy(t.ss[6:], net.ParseIP(address.String()).To16())
	default:
		return t, errors.New("unknown socket type")
	}
	t.prefixLen = prefixLen
	t.keyLen = uint16(len(key))
	copy(t.key[0:], []byte(key))
	return t, nil
}

// SetTCPMD5Signature sets a tcp md5 signature on a socket for the provided
// address, prefix length, and key. This function is only supported on Linux. To
// unset a signature provide an empty key. Prefix length is ignored on kernels
// < 4.13.
//
// https://tools.ietf.org/html/rfc2385
func SetTCPMD5Signature(fd int, address net.IP, prefixLen uint8,
	key string) error {
	t, err := newTCPMD5Sig(fd, address, prefixLen, key)
	if err != nil {
		return err
	}
	b := *(*[unsafe.Sizeof(t)]byte)(unsafe.Pointer(&t))
	return unix.SetsockoptString(fd, unix.IPPROTO_TCP, unix.TCP_MD5SIG_EXT,
		string(b[:]))
}
