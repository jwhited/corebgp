package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
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
)

func main() {
	flag.Parse()
	serverOpts := make([]corebgp.ServerOption, 0)
	if len(*bindAddr) > 0 {
		serverOpts = append(serverOpts, corebgp.LocalAddrs([]string{*bindAddr}))
	}
	corebgp.SetLogger(log.Print)
	srv, err := corebgp.NewServer(net.ParseIP(*routerID), serverOpts...)
	if err != nil {
		log.Fatalf("error constructing server: %v", err)
	}
	p := &plugin{}
	peerOpts := make([]corebgp.PeerOption, 0)
	if *passive {
		peerOpts = append(peerOpts, corebgp.WithPassive())
	}
	err = srv.AddPeer(corebgp.PeerConfig{
		LocalAddress:  net.ParseIP(*localAddress),
		RemoteAddress: net.ParseIP(*remoteAddress),
		LocalAS:       uint32(*localAS),
		RemoteAS:      uint32(*remoteAS),
	}, p, peerOpts...)
	if err != nil {
		log.Fatalf("error adding peer: %v", err)
	}

	srvErrCh := make(chan error)
	go func() {
		err := srv.Serve()
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

func newMPCap(afi uint16, safi uint8) corebgp.Capability {
	mpData := make([]byte, 4)
	binary.BigEndian.PutUint16(mpData, afi)
	mpData[3] = safi
	return corebgp.Capability{
		Code:  1,
		Value: mpData,
	}
}

func (p *plugin) GetCapabilities(c corebgp.PeerConfig) []corebgp.Capability {
	caps := make([]corebgp.Capability, 0)
	if *ipv4 {
		caps = append(caps, newMPCap(1, 1))
	}
	if *ipv6 {
		caps = append(caps, newMPCap(2, 1))
	}
	return caps
}

func (p *plugin) OnOpenMessage(peer corebgp.PeerConfig, routerID net.IP, capabilities []corebgp.Capability) *corebgp.Notification {
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
