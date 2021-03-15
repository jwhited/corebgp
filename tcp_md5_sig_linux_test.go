package corebgp

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// TestSetTCPMD5SignatureIPv4MappedIPv6Wildcard tests setting a tcp md5 sig for
// an ivp4 address on an ipv6 wildcard socket.
func TestSetTCPMD5SignatureIPv4MappedIPv6Wildcard(t *testing.T) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var cerr error
			cerr = c.Control(func(fdPtr uintptr) {
				fd := int(fdPtr)
				cerr = SetTCPMD5Signature(fd, net.ParseIP("127.0.0.1"),
					32, "password")
			})
			return cerr
		},
	}
	lis, err := lc.Listen(context.Background(), "tcp",
		net.JoinHostPort("::", "0"))
	if err != nil {
		t.Fatalf("error listening: %v", err)
	}
	defer lis.Close()
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("error splitting host/port: %v", err)
	}
	laddr, err := net.ResolveTCPAddr("tcp",
		net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatalf("error resolving laddr: %v", err)
	}
	dialer := &net.Dialer{
		Timeout:   time.Second,
		LocalAddr: laddr,
		Control: func(network, address string, c syscall.RawConn) error {
			var cerr error
			cerr = c.Control(func(fdPtr uintptr) {
				fd := int(fdPtr)
				cerr = SetTCPMD5Signature(fd, net.ParseIP("127.0.0.1"),
					32, "password")
			})
			return cerr
		},
	}
	conn, err := dialer.Dial("tcp4", fmt.Sprintf("127.0.0.1:%s", port))
	if err != nil {
		t.Fatalf("error dialing: %v", err)
	}
	defer conn.Close()
}

func TestSetTCPMD5Signature(t *testing.T) {
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
	var seterr error
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// nil address
		seterr = SetTCPMD5Signature(fd, nil, 32, "password")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr == nil {
		t.Fatal("nil address should fail")
	}
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// ipv6 address
		seterr = SetTCPMD5Signature(fd, net.ParseIP("2001:db8::1"), 128, "password")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr == nil {
		t.Fatal("ipv6 address on ipv4 socket should fail")
	}
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// valid
		seterr = SetTCPMD5Signature(fd, net.ParseIP("127.0.0.1"), 32, "password")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	laddr, err := net.ResolveTCPAddr("tcp",
		net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatalf("error resolving laddr: %v", err)
	}
	dialer := &net.Dialer{
		Timeout:   time.Second,
		LocalAddr: laddr,
		Control: func(network, address string, c syscall.RawConn) error {
			var cerr error
			cerr = c.Control(func(fdPtr uintptr) {
				fd := int(fdPtr)
				cerr = SetTCPMD5Signature(fd, net.ParseIP("127.0.0.1"),
					32, "password")
			})
			return cerr
		},
	}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", port))
	if err != nil {
		t.Fatalf("error dialing w/md5: %v", err)
	}
	defer conn.Close()
	err = raw.Control(func(fdPtr uintptr) {
		fd := int(fdPtr)
		// unset
		seterr = SetTCPMD5Signature(fd, net.ParseIP("127.0.0.1"), 32, "")
	})
	if err != nil {
		t.Fatalf("control err: %v", err)
	}
	if seterr != nil {
		t.Fatalf("error unsetting: %v", err)
	}
	conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", port))
	if err != nil {
		t.Fatalf("error dialing w/o md5: %v", err)
	}
	defer conn.Close()
}
