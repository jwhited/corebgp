package corebgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// PathAttrFlags represents the flags for a path attribute.
type PathAttrFlags uint8

// Optional defines whether the attribute is optional (if set to 1) or
// well-known (if set to 0).
func (p PathAttrFlags) Optional() bool {
	return 1<<7&p != 0
}

// Transitive defines whether an optional attribute is transitive (if set to 1)
// or non-transitive (if set to 0).
func (p PathAttrFlags) Transitive() bool {
	return 1<<6&p != 0
}

// Partial defines whether the information contained in the optional transitive
// attribute is partial (if set to 1) or complete (if set to 0).
func (p PathAttrFlags) Partial() bool {
	return 1<<5&p != 0
}

// ExtendedLen defines whether the Attribute Length is one octet (if set to 0)
// or two octets (if set to 1).
func (p PathAttrFlags) ExtendedLen() bool {
	return 1<<4&p != 0
}

func (p PathAttrFlags) Validate(forCode uint8, attrData []byte, wantOptional, wantTransitive bool) error {
	// https://www.rfc-editor.org/rfc/rfc7606#page-6
	// If the value of either the Optional or Transitive bits in the Attribute
	// Flags is in conflict with their specified values, then the attribute MUST
	// be treated as malformed and the "treat-as-withdraw" approach used, unless
	// the specification for the attribute mandates different handling for
	// incorrect Attribute Flags.
	if p.Optional() != wantOptional || p.Transitive() != wantTransitive {
		return &TreatAsWithdrawUpdateErr{
			Code: forCode,
			Notification: &Notification{ // fallback RFC4271 handling
				// https://www.rfc-editor.org/rfc/rfc4271#page-32
				// If any recognized attribute has Attribute Flags that conflict
				// with the Attribute Type Code, then the Error Subcode MUST be
				// set to Attribute Flags Error.  The Data field MUST contain
				// the erroneous attribute (type, length, and value).
				Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
				Subcode: NOTIF_SUBCODE_ATTR_FLAGS_ERR,
				Data:    notifDataForAttrBasedErr(forCode, attrData),
			},
		}
	}
	return nil
}

type OriginPathAttr uint8

// UpdateNotificationFromErr finds the highest severity *Notification in err's
// tree. This is useful for Plugins using UpdateDecoder that do not handle the
// additional error approaches described by RFC7606, and instead are designed to
// send a *Notification when any error occurs.
//
// The severity order from highest to lowest is *Notification,
// *TreatAsWithdrawUpdateErr, *AttrDiscardUpdateErr, UpdateError (not one of the
// previous concrete types). If there are multiple errors contained in err's
// tree of the same severity the earliest found is returned. A *Notification
// with code NOTIF_CODE_UPDATE_MESSAGE_ERR, no subcode, and no data is returned
// in the event that a *Notification cannot be extracted from err.
func UpdateNotificationFromErr(err error) *Notification {
	if err == nil {
		return nil
	}
	var (
		n   *Notification
		taw *TreatAsWithdrawUpdateErr
		ad  *AttrDiscardUpdateErr
		ue  UpdateError
	)

	var unwrap func(err error)
	unwrap = func(err error) {
		switch x := err.(type) {
		case *Notification:
			if n == nil {
				n = x
			}
			return
		case *TreatAsWithdrawUpdateErr:
			if taw == nil {
				taw = x
			}
		case *AttrDiscardUpdateErr:
			if ad == nil {
				ad = x
			}
		case UpdateError:
			if ue == nil {
				ue = x
			}
		}
		switch x := err.(type) {
		case interface{ Unwrap() error }:
			unwrap(x.Unwrap())
			if n != nil {
				return
			}
		case interface{ Unwrap() []error }:
			for _, err = range x.Unwrap() {
				unwrap(err)
				if n != nil {
					return
				}
			}
		}
	}

	unwrap(err)

	if n != nil {
		return n
	} else if taw != nil {
		return taw.AsSessionReset()
	} else if ad != nil {
		return ad.AsSessionReset()
	} else if ue != nil {
		return ue.AsSessionReset()
	}
	return &Notification{
		Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
	}
}

// UpdateError represents an error handling an UPDATE message. UpdateError is
// used throughout the decoding logic in this package. It provides the option of
// following either the UPDATE error handling originally defined in RFC4271 OR
// the revised handling defined in RFC7606.
type UpdateError interface {
	error

	// AsSessionReset returns a *Notification that can be used to represent
	// the error as a NOTIFICATION message to be sent to the remote peer. This
	// can be used where usage of UpdateDecoder does not implement the revised
	// error handling described by RFC7606, and instead intends for all errors
	// to result in a session reset.
	AsSessionReset() *Notification
}

// AttrDiscardUpdateErr represents an error encountered during UPDATE message
// handling. The usage of this error is described in
// https://www.rfc-editor.org/rfc/rfc7606#section-2
//
// Attribute discard: In this approach, the malformed attribute MUST be
// discarded and the UPDATE message continues to be processed. This approach
// MUST NOT be used except in the case of an attribute that has no effect on
// route selection or installation.
type AttrDiscardUpdateErr struct {
	Code         uint8
	Notification *Notification
}

func (a *AttrDiscardUpdateErr) AsSessionReset() *Notification {
	if a.Notification != nil {
		return a.Notification
	}
	return &Notification{
		Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
	}
}

func (a *AttrDiscardUpdateErr) Error() string {
	return fmt.Sprintf("attribute discard error for attribute code: %d", a.Code)
}

// TreatAsWithdrawUpdateErr represents an error encountered during UPDATE
// message handling. The usage of this error is described in
// https://www.rfc-editor.org/rfc/rfc7606#section-2
//
// Treat-as-withdraw: In this approach, the UPDATE message containing the path
// attribute in question MUST be treated as though all contained routes had been
// withdrawn just as if they had been listed in the WITHDRAWN ROUTES field (or
// in the MP_UNREACH_NLRI attribute if appropriate) of the UPDATE message, thus
// causing them to be removed from the Adj-RIB-In according to the procedures of
// [RFC4271].
type TreatAsWithdrawUpdateErr struct {
	Code         uint8
	Notification *Notification
}

func (t *TreatAsWithdrawUpdateErr) AsSessionReset() *Notification {
	if t.Notification != nil {
		return t.Notification
	}
	return &Notification{
		Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
	}
}

func (t *TreatAsWithdrawUpdateErr) Error() string {
	return fmt.Sprintf("treat as withdraw error for attribute code: %d", t.Code)
}

func (o *OriginPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_ORIGIN, b, false, true)
	if err != nil {
		return err
	}
	if len(b) != 1 || b[0] > 2 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-11
		// The attribute is considered malformed if its length is not 1 or if it
		// has an undefined value [RFC4271].
		//
		// An UPDATE message with a malformed ORIGIN attribute SHALL be handled
		// using the approach of "treat-as-withdraw".
		var subcode uint8
		if len(b) != 1 {
			// https://www.rfc-editor.org/rfc/rfc4271#page-33
			// If any recognized attribute has an Attribute Length that
			// conflicts with the expected length (based on the attribute type
			// code), then the Error Subcode MUST be set to Attribute Length
			// Error.  The Data field MUST contain the erroneous attribute
			// (type, length, and value).
			subcode = NOTIF_SUBCODE_ATTR_LEN_ERR
		} else {
			// https://www.rfc-editor.org/rfc/rfc4271#page-33
			// If the ORIGIN attribute has an undefined value, then the Error
			// Sub-code MUST be set to Invalid Origin Attribute.  The Data field
			// MUST contain the unrecognized attribute (type, length, and
			// value).
			subcode = NOTIF_SUBCODE_INVALID_ORIGIN_ATTR
		}
		return &TreatAsWithdrawUpdateErr{
			Code: PATH_ATTR_ORIGIN,
			Notification: &Notification{
				Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
				Subcode: subcode,
				Data:    notifDataForAttrBasedErr(PATH_ATTR_ORIGIN, b),
			},
		}
	}
	*o = OriginPathAttr(b[0])
	return nil
}

func decodeUint32Set(b []byte) ([]uint32, error) {
	if len(b) == 0 || len(b)%4 != 0 {
		return nil, fmt.Errorf("invalid uint32 set len: %d", len(b))
	}
	ret := make([]uint32, 0, len(b)/4)
	for len(b) > 0 {
		ret = append(ret, binary.BigEndian.Uint32(b))
		b = b[4:]
	}
	return ret, nil
}

func notifDataForAttrBasedErr(code uint8, attrData []byte) []byte {
	nData := make([]byte, 0, 1+2+len(attrData))
	nData = append(nData, code)
	if len(attrData) > 255 {
		extLen := make([]byte, 2)
		binary.BigEndian.PutUint16(extLen, uint16(len(attrData)))
		nData = append(nData, extLen...)
	} else {
		nData = append(nData, uint8(len(attrData)))
	}
	return append(nData, attrData...)
}

type ASPathAttr struct {
	ASSet      []uint32
	ASSequence []uint32
}

func asPathMalformedErr() error {
	return &TreatAsWithdrawUpdateErr{
		Code: PATH_ATTR_AS_PATH,
		Notification: &Notification{
			Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
			Subcode: NOTIF_SUBCODE_MALFORMED_AS_PATH,
		},
	}
}

func (a *ASPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_AS_PATH, b, false, true)
	if err != nil {
		return err
	}
	if len(b) < 6 || len(b)%2 != 0 { // corebgp requires four octet AS
		return &TreatAsWithdrawUpdateErr{
			Code:         PATH_ATTR_AS_PATH,
			Notification: attrLenBadForCodeErr(PATH_ATTR_AS_PATH, b),
		}
	}
	for len(b) > 0 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-11
		// An AS_PATH is considered malformed if an unrecognized segment type is
		// encountered or if it contains a malformed segment.  A segment is
		// considered malformed if any of the following are true:
		//
		//   o  There is an overrun where the Path Segment Length field of the
		//      last segment encountered would cause the Attribute Length to be
		//      exceeded.
		//
		//   o  There is an underrun where after the last successfully parsed
		//      segment there is only a single octet remaining (that is, there
		//      is not enough unconsumed data to provide even an empty segment
		//      header).
		//
		//   o  It has a Path Segment Length field of zero.
		//
		//   An UPDATE message with a malformed AS_PATH attribute SHALL be
		//   handled using the approach of "treat-as-withdraw".
		if len(b) < 6 || len(b)%2 != 0 {
			return &TreatAsWithdrawUpdateErr{
				Code:         PATH_ATTR_AS_PATH,
				Notification: attrLenBadForCodeErr(PATH_ATTR_AS_PATH, b),
			}
		}
		segType := b[0]
		segLen := int(b[1] * 4)
		if segLen == 0 {
			return asPathMalformedErr()
		}
		b = b[2:]
		if len(b) < segLen {
			return asPathMalformedErr()
		}
		set := b[:segLen]
		if segType == 1 {
			a.ASSet, err = decodeUint32Set(set)
			if err != nil {
				return asPathMalformedErr()
			}
		} else if segType == 2 {
			a.ASSequence, err = decodeUint32Set(set)
			if err != nil {
				return asPathMalformedErr()
			}
		} else {
			return asPathMalformedErr()
		}
		b = b[segLen:]
	}
	return nil
}

type NextHopPathAttr netip.Addr

func (n *NextHopPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_NEXT_HOP, b, false, true)
	if err != nil {
		return err
	}
	// https://www.rfc-editor.org/rfc/rfc7606#page-12
	// The attribute is considered malformed if its length is not 4 [RFC4271].
	//
	// An UPDATE message with a malformed NEXT_HOP attribute SHALL be handled
	// using the approach of "treat-as-withdraw".
	if len(b) != 4 {
		return &TreatAsWithdrawUpdateErr{
			Code:         PATH_ATTR_NEXT_HOP,
			Notification: attrLenBadForCodeErr(PATH_ATTR_NEXT_HOP, b),
		}
	}
	a, _ := netip.AddrFromSlice(b)
	*n = NextHopPathAttr(a)
	return nil
}

func decodeAddPathPrefixes(b []byte, ipv6 bool) ([]AddPathPrefix, error) {
	if len(b) < 1 {
		return nil, nil
	}
	prefixes := make([]AddPathPrefix, 0)
	for len(b) > 0 {
		if len(b) < 5 {
			return nil, fmt.Errorf("invalid octets: %d for add path prefix ipv6: %v", len(b), ipv6)
		}
		var (
			a   AddPathPrefix
			err error
		)
		a.ID = binary.BigEndian.Uint32(b)
		b = b[4:]
		a.Prefix, b, err = decodePrefix(b, ipv6)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, a)
	}
	return prefixes, nil
}

// decodePrefix decodes an IP prefix in b where prefix is of the form
// <length, prefix>. Length is expected to be a single octet indicating the
// length of the prefix in bits. Prefix contains the prefix followed by the
// minimum number of trailing bits needed to make the end fall on an octet
// boundary. If the address family of the prefix is IPv6, the ipv6 argument
// should be true, otherwise false.
func decodePrefix(b []byte, ipv6 bool) (netip.Prefix, []byte, error) {
	if len(b) < 1 {
		return netip.Prefix{}, nil, errors.New("prefix must be at least 1 byte")
	}
	bl := b[0]
	if (!ipv6 && bl > 32) || (ipv6 && bl > 128) {
		return netip.Prefix{}, nil, fmt.Errorf("invalid bit len: %d ipv6: %v", bl, ipv6)
	}
	b = b[1:]
	octets := (bl + 7) / 8
	if len(b) < int(octets) {
		return netip.Prefix{}, nil, fmt.Errorf("invalid octets: %d for bit len: %d ipv6: %v", octets, bl, ipv6)
	}
	var addr netip.Addr
	if ipv6 {
		if octets > 16 {
			return netip.Prefix{}, nil, errors.New("octets > 16 for IPv6 prefix")
		}
		var addr16 [16]byte
		copy(addr16[:], b[:octets])
		addr = netip.AddrFrom16(addr16)
	} else {
		if octets > 4 {
			return netip.Prefix{}, nil, errors.New("octets > 4 for IPv4 prefix")
		}
		var addr4 [4]byte
		copy(addr4[:], b[:octets])
		addr = netip.AddrFrom4(addr4)
	}
	return netip.PrefixFrom(addr, int(bl)), b[octets:], nil
}

func decodePrefixes(b []byte, ipv6 bool) ([]netip.Prefix, error) {
	if len(b) < 1 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0)
	for len(b) > 0 {
		var (
			p   netip.Prefix
			err error
		)
		p, b, err = decodePrefix(b, ipv6)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

type MEDPathAttr uint32

func (m *MEDPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_MED, b, true, false)
	if err != nil {
		return err
	}
	if len(b) != 4 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-12
		// The attribute is considered malformed if its length is not 4
		// [RFC4271].
		//
		// An UPDATE message with a malformed MULTI_EXIT_DISC attribute SHALL be
		// handled using the approach of "treat-as-withdraw".
		return &TreatAsWithdrawUpdateErr{
			Code:         PATH_ATTR_MED,
			Notification: attrLenBadForCodeErr(PATH_ATTR_MED, b),
		}
	}
	*m = MEDPathAttr(binary.BigEndian.Uint32(b))
	return nil
}

type LocalPrefPathAttr uint32

func (l *LocalPrefPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_LOCAL_PREF, b, true, false)
	if err != nil {
		return err
	}
	if len(b) != 4 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-12
		// The error handling of [RFC4271] is revised as follows:
		//
		//   o  if the LOCAL_PREF attribute is received from an external neighbor,
		//      it SHALL be discarded using the approach of "attribute discard";
		//      or
		//
		//   o  if received from an internal neighbor, it SHALL be considered
		//      malformed if its length is not equal to 4.  If malformed, the
		//      UPDATE message SHALL be handled using the approach of "treat-as-
		//      withdraw".
		return &TreatAsWithdrawUpdateErr{
			Code:         PATH_ATTR_LOCAL_PREF,
			Notification: attrLenBadForCodeErr(PATH_ATTR_LOCAL_PREF, b),
		}
	}
	*l = LocalPrefPathAttr(binary.BigEndian.Uint32(b))
	return nil
}

type AtomicAggregatePathAttr bool

func (a *AtomicAggregatePathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_ATOMIC_AGGREGATE, b, true, true)
	if err != nil {
		return err
	}
	if len(b) != 0 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-12
		// The attribute SHALL be considered malformed if its length is not 0
		// [RFC4271].
		//
		// An UPDATE message with a malformed ATOMIC_AGGREGATE attribute SHALL
		// be handled using the approach of "attribute discard".
		return &AttrDiscardUpdateErr{
			Code:         PATH_ATTR_ATOMIC_AGGREGATE,
			Notification: attrLenBadForCodeErr(PATH_ATTR_ATOMIC_AGGREGATE, b),
		}
	}
	*a = true
	return nil
}

type AggregatorPathAttr struct {
	AS uint32
	IP netip.Addr
}

func (a *AggregatorPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_AGGREGATOR, b, true, true)
	if err != nil {
		return err
	}
	if len(b) != 8 { // corebgp requires four octet AS
		// https://www.rfc-editor.org/rfc/rfc7606#page-13
		// The error conditions specified in [RFC4271] for the attribute are
		//   revised as follows:
		//
		//   The AGGREGATOR attribute SHALL be considered malformed if any of the
		//   following applies:
		//
		//   o  Its length is not 6 (when the 4-octet AS number capability is not
		//      advertised to or not received from the peer [RFC6793]).
		//
		//   o  Its length is not 8 (when the 4-octet AS number capability is both
		//      advertised to and received from the peer).
		//
		//   An UPDATE message with a malformed AGGREGATOR attribute SHALL be
		//   handled using the approach of "attribute discard".
		return &AttrDiscardUpdateErr{
			Code:         PATH_ATTR_AGGREGATOR,
			Notification: attrLenBadForCodeErr(PATH_ATTR_AGGREGATOR, b),
		}
	}
	(*a).AS = binary.BigEndian.Uint32(b)
	(*a).IP, _ = netip.AddrFromSlice(b[4:])
	return nil
}

type CommunitiesPathAttr []uint32

func (c *CommunitiesPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_COMMUNITY, b, true, true)
	if err != nil {
		return err
	}
	if len(b) < 4 || len(b)%4 != 0 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-13
		// The error handling of [RFC1997] is revised as follows:
		//
		//  o  The Community attribute SHALL be considered malformed if its
		//	   length is not a non-zero multiple of 4.
		//
		//  o  An UPDATE message with a malformed Community attribute SHALL be
		//	   handled using the approach of "treat-as-withdraw".
		return &TreatAsWithdrawUpdateErr{
			Code:         PATH_ATTR_COMMUNITY,
			Notification: attrLenBadForCodeErr(PATH_ATTR_COMMUNITY, b),
		}
	}
	s, _ := decodeUint32Set(b)
	*c = s
	return nil
}

type OriginatorIDPathAttr netip.Addr

func (o *OriginatorIDPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_ORIGINATOR_ID, b, true, false)
	if err != nil {
		return err
	}
	if len(b) != 4 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-13
		// The error handling of [RFC4456] is revised as follows:
		//
		//  o  if the ORIGINATOR_ID attribute is received from an external
		//     neighbor, it SHALL be discarded using the approach of "attribute
		//     discard"; or
		//
		//  o  if received from an internal neighbor, it SHALL be considered
		//     malformed if its length is not equal to 4.  If malformed, the
		//     UPDATE message SHALL be handled using the approach of "treat-as-
		//     withdraw".
		return &TreatAsWithdrawUpdateErr{
			Code:         PATH_ATTR_ORIGINATOR_ID,
			Notification: attrLenBadForCodeErr(PATH_ATTR_ORIGINATOR_ID, b),
		}
	}
	addr, _ := netip.AddrFromSlice(b)
	*o = OriginatorIDPathAttr(addr)
	return nil
}

type ClusterListPathAttr []netip.Addr

func (c *ClusterListPathAttr) Decode(flags PathAttrFlags, b []byte) error {
	err := flags.Validate(PATH_ATTR_CLUSTER_LIST, b, true, false)
	if err != nil {
		return err
	}
	if len(b) < 4 || len(b)%4 != 0 {
		// https://www.rfc-editor.org/rfc/rfc7606#page-13
		// The error handling of [RFC4456] is revised as follows:
		//
		//   o  if the CLUSTER_LIST attribute is received from an external
		//      neighbor, it SHALL be discarded using the approach of "attribute
		//      discard"; or
		//
		//   o  if received from an internal neighbor, it SHALL be considered
		//      malformed if its length is not a non-zero multiple of 4.  If
		//      malformed, the UPDATE message SHALL be handled using the approach
		//      of "treat-as-withdraw".
		return &TreatAsWithdrawUpdateErr{
			Code:         PATH_ATTR_CLUSTER_LIST,
			Notification: attrLenBadForCodeErr(PATH_ATTR_CLUSTER_LIST, b),
		}
	}
	addrs := make([]netip.Addr, 0, len(b)/4)
	for len(b) > 0 {
		addr, _ := netip.AddrFromSlice(b[:4])
		addrs = append(addrs, addr)
		b = b[4:]
	}
	*c = addrs
	return nil
}

func attrLenBadForCodeErr(code uint8, attrData []byte) *Notification {
	return &Notification{
		// https://www.rfc-editor.org/rfc/rfc4271#page-33
		// If any recognized attribute has an Attribute Length that
		// conflicts with the expected length (based on the
		// attribute type code), then the Error Subcode MUST be set
		// to Attribute Length Error.  The Data field MUST contain
		// the erroneous attribute (type, length, and value).
		Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
		Subcode: NOTIF_SUBCODE_ATTR_LEN_ERR,
		Data:    notifDataForAttrBasedErr(code, attrData),
	}
}

// AddPathPrefix is a prefix with an add-path ID.
// https://www.rfc-editor.org/rfc/rfc7911#section-3
type AddPathPrefix struct {
	Prefix netip.Prefix
	ID     uint32
}

type DecodeFn[T any] func(t T, b []byte) error

// NewNLRIAddPathDecodeFn returns a DecodeFn to be used by an UpdateDecoder for
// decoding the NLRI field of an UPDATE message containing add-path prefixes.
// The closure fn will be passed type T and a slice of AddPathPrefix.
func NewNLRIAddPathDecodeFn[T any](fn func(t T, a []AddPathPrefix) error) DecodeFn[T] {
	return func(t T, b []byte) error {
		prefixes, err := decodeAddPathPrefixes(b, false)
		if err != nil {
			// https://www.rfc-editor.org/rfc/rfc4271#page-34
			// The NLRI field in the UPDATE message is checked for syntactic
			// validity.  If the field is syntactically incorrect, then the
			// Error Subcode MUST be set to Invalid Network Field.
			return &Notification{
				Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
				Subcode: NOTIF_SUBCODE_INVALID_NETWORK_FIELD,
			}
		}
		return fn(t, prefixes)
	}
}

// NewNLRIDecodeFn returns a DecodeFn to be used by an UpdateDecoder for
// decoding the NLRI field of an UPDATE message. The closure fn will be passed
// type T and a slice of netip.Prefix.
func NewNLRIDecodeFn[T any](fn func(t T, p []netip.Prefix) error) DecodeFn[T] {
	return func(t T, b []byte) error {
		prefixes, err := decodePrefixes(b, false)
		if err != nil {
			// https://www.rfc-editor.org/rfc/rfc4271#page-34
			// The NLRI field in the UPDATE message is checked for syntactic
			// validity.  If the field is syntactically incorrect, then the
			// Error Subcode MUST be set to Invalid Network Field.
			return &Notification{
				Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
				Subcode: NOTIF_SUBCODE_INVALID_NETWORK_FIELD,
			}
		}
		return fn(t, prefixes)
	}
}

// DecodeMPReachIPv6NextHops decodes one or two (RFC2545) IPv6 next hops
// contained in nh. Error handling is consistent with RFC7606.
func DecodeMPReachIPv6NextHops(nh []byte) ([]netip.Addr, error) {
	if len(nh) != 16 && len(nh) != 32 {
		// https://datatracker.ietf.org/doc/html/rfc2545#section-3
		// The value of the Length of Next Hop Network Address field on a
		// MP_REACH_NLRI attribute shall be set to 16, when only a global
		// address is present, or 32 if a link-local address is also included in
		// the Next Hop field.
		//
		// https://www.rfc-editor.org/rfc/rfc7606#page-14
		// If the Length of Next Hop Network Address field of the MP_REACH
		// attribute is inconsistent with that which was expected, the attribute
		// is considered malformed.  Since the next hop precedes the NLRI field
		// in the attribute, in this case it will not be possible to reliably
		// locate the NLRI; thus, the "session reset" or "AFI/SAFI disable"
		// approach MUST be used.
		return nil, &Notification{
			Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
		}
	}
	nhs := make([]netip.Addr, 0, len(nh)/16)
	for len(nh) > 0 {
		addr, _ := netip.AddrFromSlice(nh[:16])
		nhs = append(nhs, addr)
		nh = nh[16:]
	}
	return nhs, nil
}

// DecodeMPIPv6AddPathPrefixes decodes IPv6 add-path prefixes in b with
// multiprotocol error handling consistent with RFC7606.
func DecodeMPIPv6AddPathPrefixes(b []byte) ([]AddPathPrefix, error) {
	prefixes, err := decodeAddPathPrefixes(b, true)
	if err != nil {
		// https://www.rfc-editor.org/rfc/rfc7606#page-7
		// Finally, we observe that in order to use the approach of "treat-
		// as-withdraw", the entire NLRI field and/or the MP_REACH_NLRI and
		// MP_UNREACH_NLRI attributes need to be successfully parsed -- what
		// this entails is discussed in more detail in Section 5.  If this
		// is not possible, the procedures of [RFC4271] and/or [RFC4760]
		// continue to apply, meaning that the "session reset" approach (or
		// the "AFI/SAFI disable" approach) MUST be followed.
		return nil, &Notification{
			Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
		}
	}
	return prefixes, nil
}

// DecodeMPIPv6Prefixes decodes IPv6 prefixes in b with multiprotocol error
// handling consistent with RFC7606.
func DecodeMPIPv6Prefixes(b []byte) ([]netip.Prefix, error) {
	prefixes, err := decodePrefixes(b, true)
	if err != nil {
		// https://www.rfc-editor.org/rfc/rfc7606#page-7
		// Finally, we observe that in order to use the approach of "treat-
		// as-withdraw", the entire NLRI field and/or the MP_REACH_NLRI and
		// MP_UNREACH_NLRI attributes need to be successfully parsed -- what
		// this entails is discussed in more detail in Section 5.  If this
		// is not possible, the procedures of [RFC4271] and/or [RFC4760]
		// continue to apply, meaning that the "session reset" approach (or
		// the "AFI/SAFI disable" approach) MUST be followed.
		return nil, &Notification{
			Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
		}
	}
	return prefixes, nil
}

// NewWithdrawnAddPathRoutesDecodeFn returns a DecodeFn to be used by an
// UpdateDecoder for decoding the withdrawn routes field of an UPDATE message
// containing add-path prefixes. The closure fn will be passed type T and
// a slice of AddPathPrefix.
func NewWithdrawnAddPathRoutesDecodeFn[T any](fn func(t T, a []AddPathPrefix) error) DecodeFn[T] {
	return func(t T, b []byte) error {
		prefixes, err := decodeAddPathPrefixes(b, false)
		if err != nil {
			// Neither RFC4271 or RFC7606 define specific error handling for
			// this case.
			return &Notification{
				Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
			}
		}
		return fn(t, prefixes)
	}
}

// NewWithdrawnRoutesDecodeFn returns a DecodeFn to be used by an UpdateDecoder
// for decoding the withdrawn routes field of an UPDATE message. The closure fn
// will be passed type T and a slice of netip.Prefix.
func NewWithdrawnRoutesDecodeFn[T any](fn func(t T, p []netip.Prefix) error) DecodeFn[T] {
	return func(t T, b []byte) error {
		prefixes, err := decodePrefixes(b, false)
		if err != nil {
			// Neither RFC4271 or RFC7606 define specific error handling for
			// this case.
			return &Notification{
				Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
			}
		}
		return fn(t, prefixes)
	}
}

type MPPathAttrDecodeFn[T any] func(t T, flags PathAttrFlags, b []byte) error

// NewMPReachNLRIDecodeFn returns a MPPathAttrDecodeFn that can be used to
// compose logic for decoding a MP_REACH_NLRI path attribute through the
// provided closure fn. The closure fn will be passed type T, the afi, safi,
// next hop bytes, and nlri bytes.
func NewMPReachNLRIDecodeFn[T any](fn func(t T, afi uint16, safi uint8, nh, nlri []byte) error) MPPathAttrDecodeFn[T] {
	return func(t T, flags PathAttrFlags, b []byte) error {
		me := flags.Validate(PATH_ATTR_MP_REACH_NLRI, b, true, false)
		if len(b) < 5 {
			return errors.Join(me, mpLenErr())
		}
		afi := binary.BigEndian.Uint16(b)
		safi := b[2]
		nhLen := b[3]
		b = b[4:]
		if len(b) < int(nhLen)+1 { // reserved byte
			return errors.Join(me, mpLenErr())
		}
		return errors.Join(me, fn(t, afi, safi, b[:nhLen], b[nhLen+1:]))
	}
}

// NewMPUnreachNLRIDecodeFn returns a MPPathAttrDecodeFn that can be used to
// compose logic for decoding a MP_UNREACH_NLRI path attribute through the
// provided closure fn. The closure fn will be passed type T, the afi, safi,
// and withdrawn field for the path attribute.
func NewMPUnreachNLRIDecodeFn[T any](fn func(t T, afi uint16, safi uint8, withdrawn []byte) error) MPPathAttrDecodeFn[T] {
	return func(t T, flags PathAttrFlags, b []byte) error {
		me := flags.Validate(PATH_ATTR_MP_UNREACH_NLRI, b, true, false)
		if len(b) < 3 {
			return errors.Join(me, mpLenErr())
		}
		afi := binary.BigEndian.Uint16(b)
		safi := b[2]
		return errors.Join(me, fn(t, afi, safi, b[3:]))
	}
}

func mpLenErr() *Notification {
	// https://www.rfc-editor.org/rfc/rfc7606#page-14
	// If the Length of Next Hop Network Address field of the MP_REACH
	// attribute is inconsistent with that which was expected, the attribute
	// is considered malformed.  Since the next hop precedes the NLRI field
	// in the attribute, in this case it will not be possible to reliably
	// locate the NLRI; thus, the "session reset" or "AFI/SAFI disable"
	// approach MUST be used.
	return &Notification{
		Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
		Subcode: NOTIF_SUBCODE_ATTR_LEN_ERR,
	}
}

// PathAttrsDecodeFn is used by an instance of an UpdateDecoder to decode path
// attributes in an UPDATE message. It is invoked per-path attribute where
// code is the attribute code, flags are the attribute flags, and b contains the
// attribute data.
type PathAttrsDecodeFn[T any] func(t T, code uint8, flags PathAttrFlags, b []byte) error

// NewUpdateDecoder returns a new instance of an UpdateDecoder where wrFn is
// used to decode withdrawn routes, paFn is used to decode path attributes, and
// nlriFn is used to decode network layer reachability info.
func NewUpdateDecoder[T any](
	wrFn DecodeFn[T],
	paFn PathAttrsDecodeFn[T],
	nlriFn DecodeFn[T],
) *UpdateDecoder[T] {
	s := &UpdateDecoder[T]{
		wrFn:   wrFn,
		paFn:   paFn,
		nlriFn: nlriFn,
	}
	return s
}

// UpdateDecoder decodes UPDATE messages. Type T can be passed to its underlying
// field-specific decode functions.
type UpdateDecoder[T any] struct {
	wrFn   DecodeFn[T]
	paFn   PathAttrsDecodeFn[T]
	nlriFn DecodeFn[T]
}

func totalAttrLenErr(code uint8) error {
	// https://www.rfc-editor.org/rfc/rfc7606#page-7
	// There are two error cases in which the Total Attribute Length
	// value can be in conflict with the enclosed path attributes, which
	// themselves carry length values:
	//
	//   o  In the first case, the length of the last encountered path
	//      attribute would cause the Total Attribute Length to be
	//      exceeded when parsing the enclosed path attributes.
	//
	//   o  In the second case, fewer than three octets remain (or fewer
	//      than four octets, if the Attribute Flags field has the
	//      Extended Length bit set) when beginning to parse the
	//      attribute.  That is, this case exists if there remains
	//      unconsumed data in the path attributes but yet insufficient
	//      data to encode a single minimum-sized path attribute.
	//
	// In either of these cases, an error condition exists and the
	// "treat-as-withdraw" approach MUST be used (unless some other,
	// more severe error is encountered dictating a stronger approach),
	// and the Total Attribute Length MUST be relied upon to enable the
	// beginning of the NLRI field to be located.
	return &TreatAsWithdrawUpdateErr{
		Code: code,
		// RFC4271 does not define specific error handling for this case.
		Notification: &Notification{
			Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
		},
	}
}

type attrsBitmap [256 / 32]uint32

func (a *attrsBitmap) set(b uint8) {
	a[b/32] |= uint32(1) << (b % 32)
}

func (a *attrsBitmap) isSet(b uint8) bool {
	return a[b/32]&uint32(1<<(b%32)) != 0
}

func (s *UpdateDecoder[T]) decodePathAttrs(t T, b []byte, hasNLRI bool) error {
	if len(b) < 1 {
		return nil
	}
	var me error
	var notif *Notification
	var attrsSeen attrsBitmap
	for len(b) > 0 {
		flags := PathAttrFlags(b[0])
		if len(b) < 2 {
			me = errors.Join(me, totalAttrLenErr(0))
			break
		}
		attrType := b[1]
		var attrLen int
		if flags.ExtendedLen() {
			if len(b) < 4 {
				me = errors.Join(me, totalAttrLenErr(attrType))
				break
			}
			attrLen = int(binary.BigEndian.Uint16(b[2:4]))
			b = b[4:]
		} else {
			if len(b) < 3 {
				me = errors.Join(me, totalAttrLenErr(attrType))
				break
			}
			attrLen = int(b[2])
			b = b[3:]
		}
		if len(b) < attrLen {
			me = errors.Join(me, totalAttrLenErr(attrType))
			break
		}
		if attrsSeen.isSet(attrType) {
			// https://www.rfc-editor.org/rfc/rfc7606#page-7
			// If the MP_REACH_NLRI attribute or the MP_UNREACH_NLRI [RFC4760]
			// attribute appears more than once in the UPDATE message, then a
			// NOTIFICATION message MUST be sent with the Error Subcode
			// "Malformed Attribute List".  If any other attribute (whether
			// recognized or unrecognized) appears more than once in an UPDATE
			// message, then all the occurrences of the attribute other than the
			// first one SHALL be discarded and the UPDATE message will continue
			// to be processed.
			if attrType == PATH_ATTR_MP_REACH_NLRI || attrType == PATH_ATTR_MP_UNREACH_NLRI {
				return errors.Join(me, &Notification{
					Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
					Subcode: NOTIF_SUBCODE_MALFORMED_ATTR_LIST,
				})
			}
			b = b[attrLen:]
			continue
		}
		attrsSeen.set(attrType)
		err := s.paFn(t, attrType, flags, b[:attrLen])
		if err != nil {
			me = errors.Join(me, err)
			if errors.As(err, &notif) {
				return me
			}
		}
		b = b[attrLen:]
	}
	if attrsSeen.isSet(PATH_ATTR_MP_REACH_NLRI) || hasNLRI {
		// https://www.rfc-editor.org/rfc/rfc7606#page-6
		// If any of the well-known mandatory attributes are not present in an
		// UPDATE message, then "treat-as-withdraw" MUST be used.  (Note that
		// [RFC4760] reclassifies NEXT_HOP as what is effectively discretionary.)
		if !attrsSeen.isSet(PATH_ATTR_AS_PATH) || !attrsSeen.isSet(PATH_ATTR_ORIGIN) {
			missingCode := PATH_ATTR_AS_PATH
			if !attrsSeen.isSet(PATH_ATTR_ORIGIN) {
				missingCode = PATH_ATTR_ORIGIN
			}
			me = errors.Join(me, &TreatAsWithdrawUpdateErr{
				Code: missingCode,
				// RFC4271 fallback handling
				// https://www.rfc-editor.org/rfc/rfc4271#page-33
				// If any of the well-known mandatory attributes are not present,
				// then the Error Subcode MUST be set to Missing Well-known
				// Attribute.  The Data field MUST contain the Attribute Type Code
				// of the missing, well-known attribute.
				Notification: &Notification{
					Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
					Subcode: NOTIF_SUBCODE_MISSING_WELL_KNOWN_ATTR,
					Data:    []byte{missingCode},
				},
			})
		}
	}
	return me
}

// Decode decodes the UPDATE message contained in b. Type T is passed to the
// field-specific decode functions. Decode may return multiple errors, which can
// be accessed via error unwrapping. See UpdateError for information on returned
// errors. UpdateNotificationFromErr can be used to extract a *Notification from
// a non-nil Decode error.
func (s *UpdateDecoder[T]) Decode(t T, b []byte) error {
	// TODO consider decode opts to get more specific / strict, e.g.
	// local/remote ASN for ASPath verification and local pref presence (should
	// not be present for ebgp)

	// withdrawn routes length + total path attributes length
	if len(b) < 4 {
		return &Notification{
			Code: NOTIF_CODE_UPDATE_MESSAGE_ERR,
		}
	}

	// https://www.rfc-editor.org/rfc/rfc4271#section-6.3
	// Error checking of an UPDATE message begins by examining the path
	// attributes.  If the Withdrawn Routes Length or Total Attribute Length
	// is too large (i.e., if Withdrawn Routes Length + Total Attribute
	// Length + 23 exceeds the message Length), then the Error Subcode MUST
	// be set to Malformed Attribute List.
	wrl := binary.BigEndian.Uint16(b[:2])
	b = b[2:]
	if len(b) < int(wrl)+2 {
		return &Notification{
			Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
			Subcode: NOTIF_SUBCODE_MALFORMED_ATTR_LIST,
		}
	}
	pal := int(binary.BigEndian.Uint16(b[wrl : wrl+2]))
	if len(b[wrl+2:]) < pal {
		return &Notification{
			Code:    NOTIF_CODE_UPDATE_MESSAGE_ERR,
			Subcode: NOTIF_SUBCODE_MALFORMED_ATTR_LIST,
		}
	}

	// withdrawn routes
	var me error
	var notif *Notification
	err := s.wrFn(t, b[:wrl])
	if err != nil {
		me = errors.Join(me, err)
		if errors.As(err, &notif) {
			return me
		}
	}
	b = b[wrl+2:]

	// path attributes
	err = s.decodePathAttrs(t, b[:pal], len(b[pal:]) > 0)
	if err != nil {
		me = errors.Join(me, err)
		if errors.As(err, &notif) {
			return me
		}
	}
	b = b[pal:]

	// nlri
	err = s.nlriFn(t, b)
	if err != nil {
		me = errors.Join(me, err)
	}
	return me
}
