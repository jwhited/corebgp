package corebgp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func TestSetTCPMD5Signature(t *testing.T) {
	// setup AF_INET wildcard socket
	lis, err := net.Listen("tcp4", ":0")
	if err != nil {
		t.Fatalf("error listening: %v", err)
	}
	defer lis.Close()
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("error splitting host/port: %v", err)
	}
	tlis, ok := lis.(*net.TCPListener)
	if !ok {
		t.Fatal("not tcp listener")
	}
	raw, err := tlis.SyscallConn()
	if err != nil {
		t.Fatalf("error getting raw conn: %v", err)
	}

	// set key w/nil addr, this should fail
	var seterr error
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// nil address
		seterr = SetTCPMD5Signature(fd, netip.Addr{}, "password")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr == nil {
		t.Fatal("nil address should fail")
	}

	// set ipv6 addr on AF_INET socket, this should fail
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// ipv6 address
		seterr = SetTCPMD5Signature(fd, netip.MustParseAddr("2001:db8::1"), "password")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr == nil {
		t.Fatal("ipv6 address on ipv4 socket should fail")
	}

	// set valid ipv4 addr/key on AF_INET socket
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// valid
		seterr = SetTCPMD5Signature(fd, netip.MustParseAddr("127.0.0.1"), "password")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// dial w/password from previously set addr, this should succeed
	laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatalf("error resolving laddr: %v", err)
	}
	dialer := &net.Dialer{
		Timeout:   time.Second,
		LocalAddr: laddr,
		Control: func(network, address string, c syscall.RawConn) error {
			err := c.Control(func(fdPtr uintptr) {
				fd := int(fdPtr)
				seterr = SetTCPMD5Signature(fd, netip.MustParseAddr("127.0.0.1"), "password")
			})
			if err != nil {
				return err
			}
			return seterr
		},
	}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", port))
	if err != nil {
		t.Fatalf("error dialing w/md5: %v", err)
	}
	defer conn.Close()

	// unset previously set password
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// unset
		seterr = SetTCPMD5Signature(fd, netip.MustParseAddr("127.0.0.1"), "")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr != nil {
		t.Fatalf("error unsetting: %v", err)
	}

	// dial w/o password, this should succeed
	conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", port))
	if err != nil {
		t.Fatalf("error dialing w/o md5: %v", err)
	}
	defer conn.Close()

	// create wildcard dual stack socket and set password for IPv4 addr, this
	// should succeed
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			err := c.Control(func(fdPtr uintptr) {
				fd := int(fdPtr)
				seterr = SetTCPMD5Signature(fd, netip.MustParseAddr("127.0.0.1"), "password")
			})
			if err != nil {
				return err
			}
			return seterr
		},
	}
	lis, err = lc.Listen(context.Background(), "tcp", net.JoinHostPort("::", "0"))
	if err != nil {
		t.Fatalf("error listening: %v", err)
	}
	defer lis.Close()
	_, port, err = net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("error splitting host/port: %v", err)
	}
	laddr, err = net.ResolveTCPAddr("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatalf("error resolving laddr: %v", err)
	}

	// dial the wildcard dual stack socket using IPv4 and previously set
	// password, this should succeed
	dialer = &net.Dialer{
		Timeout:   time.Second,
		LocalAddr: laddr,
		Control: func(network, address string, c syscall.RawConn) error {
			err := c.Control(func(fdPtr uintptr) {
				fd := int(fdPtr)
				seterr = SetTCPMD5Signature(fd, netip.MustParseAddr("127.0.0.1"), "password")
			})
			if err != nil {
				return err
			}
			return seterr
		},
	}
	conn, err = dialer.Dial("tcp4", fmt.Sprintf("127.0.0.1:%s",
		port))
	if err != nil {
		t.Fatalf("error dialing: %v", err)
	}
	defer conn.Close()
}
