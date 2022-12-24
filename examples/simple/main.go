package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/jwhited/corebgp"
)

var (
	routerID      = flag.String("id", "", "router ID")
	localAS       = flag.Uint("las", 0, "local AS")
	remoteAS      = flag.Uint("ras", 0, "remote AS")
	localAddress  = flag.String("laddr", "", "local address")
	remoteAddress = flag.String("raddr", "", "remote address")
	ipv4          = flag.Bool("v4", false, "enable ipv4 afi/safi")
	ipv6          = flag.Bool("v6", false, "enable ipv6 afi/safi")
	bindAddr      = flag.String("bind", ":179", "listen address")
	passive       = flag.Bool("passive", false, "disable outbound connections")
	md5           = flag.String("md5", "", "tcp md5 signature")
)

func main() {
	flag.Parse()
	var (
		lis net.Listener
		err error
	)
	remote := netip.MustParseAddr(*remoteAddress)
	local := netip.MustParseAddr(*localAddress)
	if len(*bindAddr) > 0 {
		lc := &net.ListenConfig{}
		if len(*md5) > 0 {
			lc.Control = func(network, address string,
				c syscall.RawConn) error {
				var seterr error
				err := c.Control(func(fdPtr uintptr) {
					fd := int(fdPtr)
					prefixLen := uint8(32)
					if !remote.Is4() {
						prefixLen = 128
					}
					seterr = corebgp.SetTCPMD5Signature(fd,
						remote, prefixLen, *md5)
				})
				if err != nil {
					return err
				}
				return seterr
			}
		}
		lis, err = lc.Listen(context.Background(), "tcp", *bindAddr)
		if err != nil {
			log.Fatalf("error constructing listener: %v", err)
		}
	}
	corebgp.SetLogger(log.Print)
	srv, err := corebgp.NewServer(netip.MustParseAddr(*routerID))
	if err != nil {
		log.Fatalf("error constructing server: %v", err)
	}
	p := &plugin{}
	peerOpts := make([]corebgp.PeerOption, 0)
	if len(*md5) > 0 {
		peerOpts = append(peerOpts, corebgp.WithDialerControl(
			func(network, address string, c syscall.RawConn) error {
				var seterr error
				err := c.Control(func(fdPtr uintptr) {
					fd := int(fdPtr)
					prefixLen := uint8(32)
					if !remote.Is4() {
						prefixLen = 128
					}
					seterr = corebgp.SetTCPMD5Signature(fd,
						remote, prefixLen, *md5)
				})
				if err != nil {
					return err
				}
				return seterr
			}))
	}
	if *passive {
		peerOpts = append(peerOpts, corebgp.WithPassive())
	}
	peerOpts = append(peerOpts, corebgp.WithLocalAddress(local))
	err = srv.AddPeer(corebgp.PeerConfig{
		RemoteAddress: remote,
		LocalAS:       uint32(*localAS),
		RemoteAS:      uint32(*remoteAS),
	}, p, peerOpts...)
	if err != nil {
		log.Fatalf("error adding peer: %v", err)
	}

	srvErrCh := make(chan error)
	go func() {
		err := srv.Serve([]net.Listener{lis})
		srvErrCh <- err
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
		log.Println("got signal")
		srv.Close()
		<-srvErrCh
	case err := <-srvErrCh:
		log.Fatalf("serve error: %v", err)
	}
}

type plugin struct {
}

func (p *plugin) GetCapabilities(c corebgp.PeerConfig) []corebgp.Capability {
	caps := make([]corebgp.Capability, 0)
	if *ipv4 {
		caps = append(caps, corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV4, corebgp.SAFI_UNICAST))
	}
	if *ipv6 {
		caps = append(caps, corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV6, corebgp.SAFI_UNICAST))
	}
	return caps
}

func (p *plugin) OnOpenMessage(peer corebgp.PeerConfig, routerID netip.Addr, capabilities []corebgp.Capability) *corebgp.Notification {
	log.Println("open message received")
	return nil
}

func (p *plugin) OnEstablished(peer corebgp.PeerConfig, writer corebgp.UpdateMessageWriter) corebgp.UpdateMessageHandler {
	log.Println("peer established")
	// send End-of-Rib
	writer.WriteUpdate([]byte{0, 0, 0, 0})
	return p.handleUpdate
}

func (p *plugin) OnClose(peer corebgp.PeerConfig) {
	log.Println("peer closed")
}

func (p *plugin) handleUpdate(peer corebgp.PeerConfig, u []byte) *corebgp.Notification {
	log.Printf("got update message of len: %d", len(u))
	return nil
}
