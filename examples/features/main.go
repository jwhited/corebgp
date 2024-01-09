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
	addPath       = flag.Bool("add-path", false, "enable add-path")
)

type updateMessage struct {
	addPathIPv4          bool
	addPathIPv6          bool
	withdrawn            []netip.Prefix
	addPathWithdrawn     []corebgp.AddPathPrefix
	origin               uint8
	asPath               []uint32
	nextHop              netip.Addr
	communities          []uint32
	largeCommunities     corebgp.LargeCommunitiesPathAttr
	localPref            uint32
	med                  uint32
	nlri                 []netip.Prefix
	addPathNLRI          []corebgp.AddPathPrefix
	ipv6NextHops         []netip.Addr
	ipv6NLRI             []netip.Prefix
	addPathIPv6NLRI      []corebgp.AddPathPrefix
	ipv6Withdrawn        []netip.Prefix
	addPathIPv6Withdrawn []corebgp.AddPathPrefix
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
	largeCommsFmt := func(in corebgp.LargeCommunitiesPathAttr) []string {
		lc := make([]string, 0, len(in))
		for _, c := range in {
			lc = append(lc, fmt.Sprintf("%d:%d:%d", c.GlobalAdmin, c.LocalData1, c.LocalData2))
		}
		return lc
	}
	var sb strings.Builder
	fmtSlice[netip.Prefix](u.nlri, "nlri", &sb)
	fmtSlice[netip.Prefix](u.ipv6NLRI, "ipv6NLRI", &sb)
	fmtSlice[corebgp.AddPathPrefix](u.addPathNLRI, "addPathNLRI", &sb)
	fmtSlice[corebgp.AddPathPrefix](u.addPathIPv6NLRI, "addPathIPv6NLRI", &sb)
	if len(u.nlri) > 0 || len(u.ipv6NLRI) > 0 || len(u.addPathNLRI) > 0 || len(u.addPathIPv6NLRI) > 0 {
		sb.WriteString(fmt.Sprintf(" origin=%v", u.origin))
		if len(u.nlri) > 0 {
			sb.WriteString(fmt.Sprintf(" nextHop=%v", u.nextHop))
		}
		if len(u.ipv6NLRI) > 0 {
			fmtSlice[netip.Addr](u.ipv6NextHops, "ipv6NextHops", &sb)
		}
	}
	if u.med > 0 {
		sb.WriteString(fmt.Sprintf(" med=%d", u.med))
	}
	if u.localPref > 0 {
		sb.WriteString(fmt.Sprintf(" localPref=%d", u.localPref))
	}
	fmtSlice[uint32](u.asPath, "asPath", &sb)
	fmtSlice[string](commsFmt(u.communities), "communities", &sb)
	fmtSlice[string](largeCommsFmt(u.largeCommunities), "large-communities", &sb)
	fmtSlice[netip.Prefix](u.withdrawn, "withdrawn", &sb)
	fmtSlice[netip.Prefix](u.ipv6Withdrawn, "ipv6Withdrawn", &sb)
	fmtSlice[corebgp.AddPathPrefix](u.addPathWithdrawn, "addPathWithdrawn", &sb)
	fmtSlice[corebgp.AddPathPrefix](u.addPathIPv6Withdrawn, "addPathIPv6Withdrawn", &sb)
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
				if m.addPathIPv6 {
					prefixes, err := corebgp.DecodeMPIPv6AddPathPrefixes(nlri)
					if err != nil {
						return err
					}
					m.addPathIPv6NLRI = prefixes
				} else {
					prefixes, err := corebgp.DecodeMPIPv6Prefixes(nlri)
					if err != nil {
						return err
					}
					m.ipv6NLRI = prefixes
				}

				m.ipv6NextHops = nhs
			}
			return nil
		},
	)
	unreachDecodeFn := corebgp.NewMPUnreachNLRIDecodeFn[*updateMessage](
		func(m *updateMessage, afi uint16, safi uint8, withdrawn []byte) error {
			if afi == corebgp.AFI_IPV6 && safi == corebgp.SAFI_UNICAST {
				if m.addPathIPv6 {
					prefixes, err := corebgp.DecodeMPIPv6AddPathPrefixes(withdrawn)
					if err != nil {
						return err
					}
					m.addPathIPv6Withdrawn = prefixes
				} else {
					prefixes, err := corebgp.DecodeMPIPv6Prefixes(withdrawn)
					if err != nil {
						return err
					}
					m.ipv6Withdrawn = prefixes
				}
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
		case corebgp.PATH_ATTR_LOCAL_PREF:
			var lpref corebgp.LocalPrefPathAttr
			if err := lpref.Decode(flags, b); err != nil {
				return err
			}
			m.localPref = uint32(lpref)
		case corebgp.PATH_ATTR_LARGE_COMMUNITY:
			var lc corebgp.LargeCommunitiesPathAttr
			if err := lc.Decode(flags, b); err != nil {
				return err
			}
			m.largeCommunities = lc
		case corebgp.PATH_ATTR_MED:
			var med corebgp.MEDPathAttr
			if err := med.Decode(flags, b); err != nil {
				return err
			}
			m.med = uint32(med)
		case corebgp.PATH_ATTR_MP_REACH_NLRI:
			return reachDecodeFn(m, flags, b)
		case corebgp.PATH_ATTR_MP_UNREACH_NLRI:
			return unreachDecodeFn(m, flags, b)
		}
		return nil
	}
}

type plugin struct {
	ud                       *corebgp.UpdateDecoder[*updateMessage]
	addPathIPv4, addPathIPv6 bool
}

func (p *plugin) GetCapabilities(c corebgp.PeerConfig) []corebgp.Capability {
	caps := make([]corebgp.Capability, 0)
	if *ipv4 {
		caps = append(caps, corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV4, corebgp.SAFI_UNICAST))
	}
	if *ipv6 {
		caps = append(caps, corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV6, corebgp.SAFI_UNICAST))
	}
	if *addPath {
		tuples := make([]corebgp.AddPathTuple, 0)
		tuples = append(tuples, corebgp.AddPathTuple{
			AFI:  corebgp.AFI_IPV4,
			SAFI: corebgp.SAFI_UNICAST,
			Tx:   true,
			Rx:   true,
		})
		if *ipv6 {
			tuples = append(tuples, corebgp.AddPathTuple{
				AFI:  corebgp.AFI_IPV6,
				SAFI: corebgp.SAFI_UNICAST,
				Tx:   true,
				Rx:   true,
			})
		}
		caps = append(caps, corebgp.NewAddPathCapability(tuples))
	}
	return caps
}

func (p *plugin) OnOpenMessage(peer corebgp.PeerConfig, routerID netip.Addr, capabilities []corebgp.Capability) *corebgp.Notification {
	log.Println("open message received")
	if *addPath {
		p.addPathIPv4 = false
		p.addPathIPv6 = false
		for _, c := range capabilities {
			if c.Code != corebgp.CAP_ADD_PATH {
				continue
			}
			tuples, err := corebgp.DecodeAddPathTuples(c.Value)
			if err != nil {
				return err.(*corebgp.Notification)
			}
			for _, tuple := range tuples {
				if tuple.SAFI != corebgp.SAFI_UNICAST || !tuple.Tx {
					continue
				}
				if tuple.AFI == corebgp.AFI_IPV4 {
					p.addPathIPv4 = true
				} else if tuple.AFI == corebgp.AFI_IPV6 {
					p.addPathIPv6 = true
				}
			}
		}
	}
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
	m := &updateMessage{
		addPathIPv4: p.addPathIPv4,
		addPathIPv6: p.addPathIPv6,
	}
	err := p.ud.Decode(m, b)
	if err != nil {
		return corebgp.UpdateNotificationFromErr(err)
	}
	log.Printf("got update message: %s", m)
	return nil
}

func newWithdrawnRoutesDecodeFn() corebgp.DecodeFn[*updateMessage] {
	fn := corebgp.NewWithdrawnRoutesDecodeFn[*updateMessage](func(u *updateMessage, p []netip.Prefix) error {
		u.withdrawn = p
		return nil
	})
	apFn := corebgp.NewWithdrawnAddPathRoutesDecodeFn[*updateMessage](func(u *updateMessage, a []corebgp.AddPathPrefix) error {
		u.addPathWithdrawn = a
		return nil
	})
	return func(u *updateMessage, b []byte) error {
		if u.addPathIPv4 {
			return apFn(u, b)
		}
		return fn(u, b)
	}
}

func newNLRIDecodeFn() corebgp.DecodeFn[*updateMessage] {
	fn := corebgp.NewNLRIDecodeFn[*updateMessage](func(u *updateMessage, p []netip.Prefix) error {
		u.nlri = p
		return nil
	})
	apFn := corebgp.NewNLRIAddPathDecodeFn[*updateMessage](func(u *updateMessage, a []corebgp.AddPathPrefix) error {
		u.addPathNLRI = a
		return nil
	})
	return func(u *updateMessage, b []byte) error {
		if u.addPathIPv4 {
			return apFn(u, b)
		}
		return fn(u, b)
	}
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
			newWithdrawnRoutesDecodeFn(),
			newPathAttrsDecodeFn(),
			newNLRIDecodeFn(),
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
	case sig := <-sigCh:
		log.Printf("got signal: %s", sig)
		srv.Close()
		<-srvErrCh
	case err := <-srvErrCh:
		log.Fatalf("serve error: %v", err)
	}
}
