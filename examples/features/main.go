package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
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

type updateMessage struct {
	withdrawn     []netip.Prefix
	origin        uint8
	asPath        []uint32
	nextHop       netip.Addr
	communities   []uint32
	nlri          []netip.Prefix
	ipv6NextHops  []netip.Addr
	ipv6NLRI      []netip.Prefix
	ipv6Withdrawn []netip.Prefix
}

func fmtSlice[T any](t []T, name string, sb *strings.Builder) {
	if len(t) > 0 {
		if sb.Len() > 0 {
			sb.WriteString(" ")
		}
		sb.WriteString(fmt.Sprintf("%s=%v", name, t))
	}
}

func (u updateMessage) String() string {
	commsFmt := func(in []uint32) []string {
		comms := make([]string, 0, len(in))
		for _, c := range in {
			comms = append(comms, fmt.Sprintf("%d:%d", c>>16, c&0x0000FFFF))
		}
		return comms
	}
	var sb strings.Builder
	fmtSlice[netip.Prefix](u.nlri, "nlri", &sb)
	fmtSlice[netip.Prefix](u.ipv6NLRI, "ipv6NLRI", &sb)
	if len(u.nlri) > 0 || len(u.ipv6NLRI) > 0 {
		sb.WriteString(fmt.Sprintf(" origin=%v", u.origin))
		if len(u.nlri) > 0 {
			sb.WriteString(fmt.Sprintf(" nextHop=%v", u.nextHop))
		}
		if len(u.ipv6NLRI) > 0 {
			fmtSlice[netip.Addr](u.ipv6NextHops, "ipv6NextHops", &sb)
		}
	}
	fmtSlice[uint32](u.asPath, "asPath", &sb)
	fmtSlice[string](commsFmt(u.communities), "communities", &sb)
	fmtSlice[netip.Prefix](u.withdrawn, "withdrawn", &sb)
	fmtSlice[netip.Prefix](u.ipv6Withdrawn, "ipv6Withdrawn", &sb)
	if sb.Len() == 0 {
		return "End-of-RIB"
	}
	return sb.String()
}

func newPathAttrsDecodeFn() func(m *updateMessage, code uint8, flags corebgp.PathAttrFlags, b []byte) error {
	reachDecodeFn := corebgp.NewMPReachNLRIDecodeFn[*updateMessage](
		func(m *updateMessage, afi uint16, safi uint8, nh, nlri []byte) error {
			if afi == corebgp.AFI_IPV6 && safi == corebgp.SAFI_UNICAST {
				nhs, err := corebgp.DecodeMPReachIPv6NextHops(nh)
				if err != nil {
					return err
				}
				prefixes, err := corebgp.DecodeMPIPv6Prefixes(nlri)
				if err != nil {
					return err
				}
				m.ipv6NextHops = nhs
				m.ipv6NLRI = prefixes
			}
			return nil
		},
	)
	unreachDecodeFn := corebgp.NewMPUnreachNLRIDecodeFn[*updateMessage](
		func(m *updateMessage, afi uint16, safi uint8, withdrawn []byte) error {
			if afi == corebgp.AFI_IPV6 && safi == corebgp.SAFI_UNICAST {
				prefixes, err := corebgp.DecodeMPIPv6Prefixes(withdrawn)
				if err != nil {
					return err
				}
				m.ipv6Withdrawn = prefixes
			}
			return nil
		},
	)
	return func(m *updateMessage, code uint8, flags corebgp.PathAttrFlags, b []byte) error {
		switch code {
		case corebgp.PATH_ATTR_ORIGIN:
			var o corebgp.OriginPathAttr
			err := o.Decode(flags, b)
			if err != nil {
				return err
			}
			m.origin = uint8(o)
			return nil
		case corebgp.PATH_ATTR_AS_PATH:
			var a corebgp.ASPathAttr
			err := a.Decode(flags, b)
			if err != nil {
				return err
			}
			m.asPath = a.ASSequence
			return nil
		case corebgp.PATH_ATTR_NEXT_HOP:
			var nh corebgp.NextHopPathAttr
			err := nh.Decode(flags, b)
			if err != nil {
				return err
			}
			m.nextHop = netip.Addr(nh)
			return nil
		case corebgp.PATH_ATTR_COMMUNITY:
			var comms corebgp.CommunitiesPathAttr
			err := comms.Decode(flags, b)
			if err != nil {
				return err
			}
			m.communities = comms
		case corebgp.PATH_ATTR_MP_REACH_NLRI:
			return reachDecodeFn(m, flags, b)
		case corebgp.PATH_ATTR_MP_UNREACH_NLRI:
			return unreachDecodeFn(m, flags, b)
		}
		return nil
	}
}

type plugin struct {
	ud *corebgp.UpdateDecoder[*updateMessage]
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

func (p *plugin) handleUpdate(peer corebgp.PeerConfig, b []byte) *corebgp.Notification {
	m := &updateMessage{}
	err := p.ud.Decode(m, b)
	if err != nil {
		return corebgp.UpdateNotificationFromErr(err)
	}
	log.Printf("got update message: %s", m)
	return nil
}

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
	p := &plugin{
		ud: corebgp.NewUpdateDecoder[*updateMessage](
			corebgp.NewWithdrawnRoutesDecodeFn(func(m *updateMessage, r []netip.Prefix) error {
				m.withdrawn = r
				return nil
			}),
			newPathAttrsDecodeFn(),
			corebgp.NewNLRIDecodeFn(func(m *updateMessage, r []netip.Prefix) error {
				m.nlri = r
				return nil
			}),
		),
	}
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
