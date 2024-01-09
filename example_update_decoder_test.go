package corebgp_test

import (
	"fmt"
	"net/netip"

	"github.com/jwhited/corebgp"
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

// ExampleUpdateDecoder demonstrates an UpdateDecoder that decodes UPDATE
// messages containing IPv4 and IPv6 routes.
func ExampleUpdateDecoder() {
	ud := corebgp.NewUpdateDecoder[*updateMessage](
		corebgp.NewWithdrawnRoutesDecodeFn[*updateMessage](func(u *updateMessage, withdrawn []netip.Prefix) error {
			u.withdrawn = withdrawn
			return nil
		}),
		newPathAttrsDecodeFn(),
		corebgp.NewNLRIDecodeFn[*updateMessage](func(u *updateMessage, nlri []netip.Prefix) error {
			u.nlri = nlri
			return nil
		}),
	)

	m := &updateMessage{}
	fmt.Println("=== ipv4 ===")
	fmt.Println(ud.Decode(m, []byte{
		0x00, 0x03, // withdrawn routes length
		0x10, 0x0a, 0x00, // withdrawn 10.0.0.0/16
		0x00, 0x1b, // total path attr len
		0x40, 0x01, 0x01, 0x01, // origin egp
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xea, // as path 65002
		0x40, 0x03, 0x04, 0xc0, 0x00, 0x02, 0x02, // next hop 192.0.2.2
		0xc0, 0x08, 0x04, 0xfd, 0xea, 0xff, 0xff, // communities 65002:65535
		0x18, 0xc0, 0x00, 0x02, // nlri 192.0.2.0/24
	}))
	fmt.Println(m.withdrawn)
	fmt.Println(m.origin)
	fmt.Println(m.asPath)
	fmt.Println(m.nextHop)
	fmt.Println(m.nlri)
	fmt.Println(m.communities)

	m = &updateMessage{}
	fmt.Println("=== ipv6 ===")
	fmt.Println(ud.Decode(m, []byte{
		0x00, 0x00, // withdrawn routes length
		0x00, 0x3f, // total path attr len
		// extended len MP_REACH_NLRI 2001:db8::/64 nhs 2001:db8::2 & fe80::42:c0ff:fe00:202
		0x90, 0x0e, 0x00, 0x2e, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0xc0, 0xff, 0xfe, 0x00, 0x02, 0x02, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x01, 0x01, // origin egp
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xea, // as path 65002
	}))
	fmt.Println(m.origin)
	fmt.Println(m.asPath)
	fmt.Println(m.ipv6NextHops)
	fmt.Println(m.ipv6NLRI)

	// Output:
	// === ipv4 ===
	// <nil>
	// [10.0.0.0/16]
	// 1
	// [65002]
	// 192.0.2.2
	// [192.0.2.0/24]
	// [4260036607]
	// === ipv6 ===
	// <nil>
	// 1
	// [65002]
	// [2001:db8::2 fe80::42:c0ff:fe00:202]
	// [2001:db8::/64]
}
