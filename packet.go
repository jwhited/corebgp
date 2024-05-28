package corebgp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"
)

const (
	openMessageType         = 1
	updateMessageType       = 2
	notificationMessageType = 3
	keepAliveMessageType    = 4
)

type message interface {
	messageType() uint8
}

const (
	headerLength = 19
)

func messageFromBytes(b []byte, messageType uint8) (message, error) {
	switch messageType {
	case openMessageType:
		o := &openMessage{}
		err := o.decode(b)
		if err != nil {
			return nil, err
		}
		return o, nil
	case updateMessageType:
		u := make([]byte, len(b))
		copy(u, b)
		return updateMessage(u), nil
	case notificationMessageType:
		n := &Notification{}
		err := n.decode(b)
		if err != nil {
			return nil, err
		}
		return n, nil
	case keepAliveMessageType:
		k := &keepAliveMessage{}
		return k, nil
	default:
		badType := make([]byte, 1)
		badType[0] = messageType
		n := newNotification(NOTIF_CODE_MESSAGE_HEADER_ERR,
			NOTIF_SUBCODE_BAD_MESSAGE_TYPE, badType)
		return nil, newNotificationError(n, true)
	}
}

func prependHeader(m []byte, t uint8) []byte {
	b := make([]byte, headerLength)
	for i := 0; i < 16; i++ {
		b[i] = 0xFF
	}
	msgLen := uint16(len(m) + headerLength)
	binary.BigEndian.PutUint16(b[16:], msgLen)
	b[18] = t
	b = append(b, m...)
	return b
}

type AddPathTuple struct {
	AFI  uint16
	SAFI uint8
	Tx   bool
	Rx   bool
}

func DecodeAddPathTuples(b []byte) ([]AddPathTuple, error) {
	if len(b) == 0 || len(b)%4 != 0 {
		return nil, &Notification{
			Code: NOTIF_CODE_OPEN_MESSAGE_ERR,
		}
	}
	tuples := make([]AddPathTuple, 0, len(b)/4)
	for len(b) > 0 {
		var a AddPathTuple
		err := a.Decode(b)
		if err != nil {
			return nil, err
		}
		tuples = append(tuples, a)
		b = b[4:]
	}
	return tuples, nil
}

func (a *AddPathTuple) Decode(b []byte) error {
	if len(b) < 4 {
		return &Notification{
			Code: NOTIF_CODE_OPEN_MESSAGE_ERR,
		}
	}
	a.AFI = binary.BigEndian.Uint16(b)
	a.SAFI = b[2]
	switch b[3] {
	case 3:
		a.Tx = true
		a.Rx = true
	case 2:
		a.Tx = true
	case 1:
		a.Rx = true
	default:
		return &Notification{
			Code: NOTIF_CODE_OPEN_MESSAGE_ERR,
		}
	}
	return nil
}

func (a *AddPathTuple) Encode() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b, a.AFI)
	b[2] = a.SAFI
	switch {
	// https://www.rfc-editor.org/rfc/rfc7911#page-4
	// Send/Receive:
	//  This field indicates whether the sender is (a) able to receive
	//  multiple paths from its peer (value 1), (b) able to send
	//  multiple paths to its peer (value 2), or (c) both (value 3) for
	//  the <AFI, SAFI>.
	case a.Tx && a.Rx:
		b[3] = 3
	case a.Tx:
		b[3] = 2
	case a.Rx:
		b[3] = 1
	}
	return b
}

// NewAddPathCapability returns an add-path Capability for the provided
// AddPathTuples.
func NewAddPathCapability(tuples []AddPathTuple) Capability {
	value := make([]byte, 0, 4*len(tuples))
	for _, tuple := range tuples {
		value = append(value, tuple.Encode()...)
	}
	return Capability{
		Code:  CAP_ADD_PATH,
		Value: value,
	}
}

// NewMPExtensionsCapability returns a Multiprotocol Extensions Capability for
// the provided AFI and SAFI.
func NewMPExtensionsCapability(afi uint16, safi uint8) Capability {
	mpData := make([]byte, 4)
	binary.BigEndian.PutUint16(mpData, afi)
	mpData[3] = safi
	return Capability{
		Code:  CAP_MP_EXTENSIONS,
		Value: mpData,
	}
}

// Notification is a Notification message.
type Notification struct {
	Code    uint8
	Subcode uint8
	Data    []byte
}

func newNotification(code, subcode uint8, data []byte) *Notification {
	return &Notification{
		Code:    code,
		Subcode: subcode,
		Data:    data,
	}
}

func (n *Notification) messageType() uint8 {
	return notificationMessageType
}

func (n *Notification) decode(b []byte) error {
	/*
		   If a peer sends a NOTIFICATION message, and the receiver of the
			 message detects an error in that message, the receiver cannot use a
			 NOTIFICATION message to report this error back to the peer.  Any such
			 error (e.g., an unrecognized Error Code or Error Subcode) SHOULD be
			 noticed, logged locally, and brought to the attention of the
			 administration of the peer.  The means to do this, however, lies
			 outside the scope of this document.
	*/
	if len(b) < 2 {
		return errors.New("notification message too short")
	}
	n.Code = b[0]
	n.Subcode = b[1]
	if len(b) > 2 {
		n.Data = make([]byte, len(b)-2)
		copy(n.Data, b[2:])
	}
	return nil
}

func (n *Notification) encode() ([]byte, error) {
	b := make([]byte, 2)
	b[0] = n.Code
	b[1] = n.Subcode
	if len(n.Data) > 1 {
		b = append(b, n.Data...)
	}
	return prependHeader(b, notificationMessageType), nil
}

func (n *Notification) Error() string {
	var codeDesc, subcodeDesc string
	d, ok := notifCodesMap[n.Code]
	if ok {
		codeDesc = d.desc
		s, ok := d.subcodes[n.Subcode]
		if ok {
			subcodeDesc = s
		}
	}
	return fmt.Sprintf("notification code:%d (%s) subcode:%d (%s)",
		n.Code, codeDesc, n.Subcode, subcodeDesc)
}

func (n *Notification) AsSessionReset() *Notification {
	return n
}

type openMessage struct {
	version        uint8
	asn            uint16
	holdTime       uint16
	bgpID          uint32
	optionalParams []optionalParam
}

func (o *openMessage) messageType() uint8 {
	return openMessageType
}

// https://tools.ietf.org/html/rfc4271#section-6.2
func (o *openMessage) validate(localID, localAS, remoteAS uint32) error {
	if o.version != 4 {
		version := make([]byte, 2)
		binary.BigEndian.PutUint16(version, uint16(4))
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
			NOTIF_SUBCODE_UNSUPPORTED_VERSION_NUM, version)
		return newNotificationError(n, true)
	}
	var fourOctetAS, fourOctetASFound bool
	if o.asn == asTrans {
		fourOctetAS = true
	} else if uint32(o.asn) != remoteAS {
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
			NOTIF_SUBCODE_BAD_PEER_AS, nil)
		return newNotificationError(n, true)
	}
	if o.holdTime < 3 && o.holdTime != 0 {
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
			NOTIF_SUBCODE_UNACCEPTABLE_HOLD_TIME, nil)
		return newNotificationError(n, true)
	}
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], o.bgpID)
	addr := netip.AddrFrom4(id)
	if addr.IsMulticast() {
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
			NOTIF_SUBCODE_BAD_BGP_ID, nil)
		return newNotificationError(n, true)
	}
	// https://tools.ietf.org/html/rfc6286#section-2.2
	if localAS == remoteAS && localID == o.bgpID {
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
			NOTIF_SUBCODE_BAD_BGP_ID, nil)
		return newNotificationError(n, true)
	}
	caps := o.getCapabilities()
	for _, c := range caps {
		if c.Code == CAP_FOUR_OCTET_AS {
			fourOctetASFound = true
			if len(c.Value) != 4 {
				n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR, 0, nil)
				return newNotificationError(n, true)
			}
			if binary.BigEndian.Uint32(c.Value) != remoteAS {
				n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
					NOTIF_SUBCODE_BAD_PEER_AS, nil)
				return newNotificationError(n, true)
			}
		}
	}
	if fourOctetAS && !fourOctetASFound {
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
			NOTIF_SUBCODE_BAD_PEER_AS, nil)
		return newNotificationError(n, true)
	} else if !fourOctetASFound {
		// corebgp requires four-octet ASN space support
		//
		// https://www.rfc-editor.org/rfc/rfc5492.html#section-5
		// This document defines a new Error Subcode, Unsupported Capability.
		// The value of this Subcode is 7.  The Data field in the NOTIFICATION
		// message MUST list the set of capabilities that causes the speaker to
		// send the message.  Each such capability is encoded in the same way as
		// it would be encoded in the OPEN message.
		//
		// As explained in the "Overview of Operations" section, the Unsupported
		// Capability NOTIFICATION is a way for a BGP speaker to complain that
		// its peer does not support a required capability without which the
		// peering cannot proceed.  It MUST NOT be used when a BGP speaker
		// receives a capability that it does not understand; such capabilities
		// MUST be ignored.
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
			NOTIF_SUBCODE_UNSUPPORTED_CAPABILITY, newFourOctetASCap(remoteAS).encode())
		return newNotificationError(n, true)
	}
	return nil
}

func (o *openMessage) getCapabilities() []Capability {
	caps := make([]Capability, 0)
	for _, param := range o.optionalParams {
		p, isCap := param.(*capabilityOptionalParam)
		if isCap {
			caps = append(caps, p.capabilities...)
		}
	}
	return caps
}

func (o *openMessage) decode(b []byte) error {
	if len(b) < 10 {
		n := newNotification(NOTIF_CODE_MESSAGE_HEADER_ERR,
			NOTIF_SUBCODE_BAD_MESSAGE_LEN, b)
		return newNotificationError(n, true)
	}
	o.version = b[0]
	o.asn = binary.BigEndian.Uint16(b[1:3])
	o.holdTime = binary.BigEndian.Uint16(b[3:5])
	o.bgpID = binary.BigEndian.Uint32(b[5:9])
	optionalParamsLen := int(b[9])
	if optionalParamsLen != len(b)-10 {
		n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR, 0, nil)
		return newNotificationError(n, true)
	}
	optionalParams, err := decodeOptionalParams(b[10:])
	if err != nil {
		return err
	}
	o.optionalParams = optionalParams
	return nil
}

func decodeOptionalParams(b []byte) ([]optionalParam, error) {
	params := make([]optionalParam, 0)
	for {
		if len(b) < 2 {
			n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR, 0, nil)
			return nil, newNotificationError(n, true)
		}
		paramCode := b[0]
		paramLen := b[1]
		if len(b) < int(paramLen)+2 {
			n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR, 0, nil)
			return nil, newNotificationError(n, true)
		}
		paramToDecode := make([]byte, 0)
		if paramLen > 0 {
			paramToDecode = b[2 : paramLen+2]
		}
		nextParam := 2 + int(paramLen)
		b = b[nextParam:]
		switch paramCode {
		case capabilityOptionalParamType:
			c := &capabilityOptionalParam{}
			err := c.decode(paramToDecode)
			if err != nil {
				return nil, err
			}
			params = append(params, c)
		default:
			n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR,
				NOTIF_SUBCODE_UNSUPPORTED_OPTIONAL_PARAM, nil)
			return nil, newNotificationError(n, true)
		}
		if len(b) == 0 {
			break
		}
	}
	return params, nil
}

func (o *openMessage) encode() ([]byte, error) {
	b := make([]byte, 9)
	b[0] = o.version
	binary.BigEndian.PutUint16(b[1:3], o.asn)
	binary.BigEndian.PutUint16(b[3:5], o.holdTime)
	binary.BigEndian.PutUint32(b[5:9], o.bgpID)
	params := make([]byte, 0)
	for _, param := range o.optionalParams {
		p, err := param.encode()
		if err != nil {
			return nil, err
		}
		params = append(params, p...)
	}
	b = append(b, uint8(len(params)))
	b = append(b, params...)
	return prependHeader(b, openMessageType), nil
}

const (
	asTrans uint16 = 23456
)

func newFourOctetASCap(asn uint32) Capability {
	c := Capability{
		Code:  CAP_FOUR_OCTET_AS,
		Value: make([]byte, 4),
	}
	binary.BigEndian.PutUint32(c.Value, asn)
	return c
}

func newOpenMessage(asn uint32, holdTime time.Duration, bgpID uint32,
	caps []Capability) (*openMessage, error) {
	allCaps := make([]Capability, 0, len(caps)+1)
	allCaps = append(allCaps, newFourOctetASCap(asn))
	for _, c := range caps {
		// ignore four octet as capability as we include this implicitly above
		if c.Code != CAP_FOUR_OCTET_AS {
			allCaps = append(allCaps, c)
		}
	}
	o := &openMessage{
		version:  4,
		holdTime: uint16(holdTime.Truncate(time.Second).Seconds()),
		bgpID:    bgpID,
		optionalParams: []optionalParam{
			&capabilityOptionalParam{
				capabilities: allCaps,
			},
		},
	}
	if asn > math.MaxUint16 {
		o.asn = asTrans
	} else {
		o.asn = uint16(asn)
	}
	return o, nil
}

const (
	capabilityOptionalParamType uint8 = 2
)

type optionalParam interface {
	paramType() uint8
	encode() ([]byte, error)
	decode(b []byte) error
}

type capabilityOptionalParam struct {
	capabilities []Capability
}

func (c *capabilityOptionalParam) paramType() uint8 {
	return capabilityOptionalParamType
}

func (c *capabilityOptionalParam) decode(b []byte) error {
	for {
		if len(b) < 2 {
			n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR, 0, nil)
			return newNotificationError(n, true)
		}
		capCode := b[0]
		capLen := b[1]
		if len(b) < int(capLen)+2 {
			n := newNotification(NOTIF_CODE_OPEN_MESSAGE_ERR, 0, nil)
			return newNotificationError(n, true)
		}
		capValue := make([]byte, 0)
		if capLen > 0 {
			capValue = b[2 : capLen+2]
		}
		capability := Capability{
			Code:  capCode,
			Value: capValue,
		}
		c.capabilities = append(c.capabilities, capability)
		nextCap := 2 + int(capLen)
		b = b[nextCap:]
		if len(b) == 0 {
			return nil
		}
	}
}

func (c *capabilityOptionalParam) encode() ([]byte, error) {
	b := make([]byte, 0)
	caps := make([]byte, 0)
	if len(c.capabilities) > 0 {
		for _, capability := range c.capabilities {
			caps = append(caps, capability.encode()...)
		}
	} else {
		return nil, errors.New("empty capabilities in capability optional param")
	}
	b = append(b, capabilityOptionalParamType)
	b = append(b, uint8(len(caps)))
	b = append(b, caps...)
	return b, nil
}

// Capability is a BGP capability as defined by RFC5492.
type Capability struct {
	Code  uint8
	Value []byte
}

func (c Capability) Equal(d Capability) bool {
	if c.Code != d.Code {
		return false
	}
	return bytes.Equal(c.Value, d.Value)
}

func (c Capability) encode() []byte {
	b := make([]byte, 2+len(c.Value))
	b[0] = c.Code
	b[1] = uint8(len(c.Value))
	copy(b[2:], c.Value)
	return b
}

type updateMessage []byte

func (u updateMessage) messageType() uint8 {
	return updateMessageType
}

type keepAliveMessage struct{}

func (k keepAliveMessage) messageType() uint8 {
	return keepAliveMessageType
}

func (k keepAliveMessage) encode() ([]byte, error) {
	return prependHeader(nil, keepAliveMessageType), nil
}
