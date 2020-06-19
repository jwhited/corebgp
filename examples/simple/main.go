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
	routerID = flag.String("id", "", "router ID")
	localAS  = flag.Uint("las", 0, "local AS")
	remoteAS = flag.Uint("ras", 0, "remote AS")
	peerIP   = flag.String("ip", "", "peer IP address")
	ipv4     = flag.Bool("v4", false, "enable ipv4 afi/safi")
	ipv6     = flag.Bool("v6", false, "enable ipv6 afi/safi")
	bindAddr = flag.String("bind", ":179", "listen address")
	passive  = flag.Bool("passive", false, "disable outbound connections")
)

func main() {
	flag.Parse()
	log.Println("starting up")
	var (
		lis net.Listener
		err error
	)
	if len(*bindAddr) > 0 {
		lis, err = net.Listen("tcp", *bindAddr)
		if err != nil {
			log.Fatalf("error constructing listener: %v", err)
		}
	}
	corebgp.SetLogger(log.Print)
	srv := corebgp.NewServer()
	p := &plugin{}
	opts := make([]corebgp.PeerOption, 0)
	if *passive {
		opts = append(opts, corebgp.Passive())
	}
	rid := net.ParseIP(*routerID).To4()
	if rid == nil {
		log.Fatal("invalid router ID")
	}
	err = srv.AddPeer(&corebgp.PeerConfig{
		RouterID: binary.BigEndian.Uint32(rid),
		IP:       net.ParseIP(*peerIP),
		LocalAS:  uint32(*localAS),
		RemoteAS: uint32(*remoteAS),
	}, p, opts...)
	if err != nil {
		log.Fatalf("error adding peer: %v", err)
	}

	srvErrCh := make(chan error)
	go func() {
		err := srv.Serve(lis)
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

func (p *plugin) GetCapabilities(c *corebgp.PeerConfig) []*corebgp.Capability {
	log.Println("get capabilities called")
	caps := make([]*corebgp.Capability, 0)

	if *ipv4 {
		// multiprotocol extensions
		mpData := make([]byte, 4)
		// ipv4 afi
		binary.BigEndian.PutUint16(mpData, 1)
		// safi unicast
		mpData[3] = 1
		caps = append(caps, &corebgp.Capability{
			Code:  1,
			Value: mpData,
		})
	}
	if *ipv6 {
		// multiprotocol extensions
		mpData := make([]byte, 4)
		// ipv4 afi
		binary.BigEndian.PutUint16(mpData, 2)
		// safi unicast
		mpData[3] = 1
		caps = append(caps, &corebgp.Capability{
			Code:  1,
			Value: mpData,
		})
	}

	return caps
}

func (p *plugin) OnOpenMessage(peer *corebgp.PeerConfig, capabilities []*corebgp.Capability) *corebgp.Notification {
	log.Println("open message received")
	return nil
}

func (p *plugin) OnEstablished(peer *corebgp.PeerConfig, writer corebgp.UpdateMessageWriter) corebgp.UpdateMessageHandler {
	log.Println("peer established")
	// send End-of-Rib
	writer.WriteUpdate([]byte{0, 0, 0, 0})
	return p.handleUpdate
}

func (p *plugin) OnClose(peer *corebgp.PeerConfig) {
	log.Println("peer closed")
}

func (p *plugin) handleUpdate(peer *corebgp.PeerConfig, u []byte) *corebgp.Notification {
	log.Printf("got update message: %v", u)
	return nil
}
