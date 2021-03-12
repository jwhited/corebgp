// +build !unit

package test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jwhited/corebgp"
)

const (
	myAddress   = "192.0.2.1"
	birdAddress = "192.0.2.2"
	myAS        = 65001
	birdAS      = 65002
)

type plugin struct {
	caps                 []corebgp.Capability
	openNotification     *corebgp.Notification
	updateMessageHandler corebgp.UpdateMessageHandler
	event                chan pluginEvent
}

type pluginEvent interface {
	at() time.Time
	peer() corebgp.PeerConfig
}

type baseEvent struct {
	t time.Time
	c corebgp.PeerConfig
}

func (b baseEvent) at() time.Time {
	return b.t
}

func (b baseEvent) peer() corebgp.PeerConfig {
	return b.c
}

type getCapsEvent struct {
	baseEvent
}

type onOpenEvent struct {
	baseEvent
	routerID net.IP
	caps     []corebgp.Capability
}

type onEstablishedEvent struct {
	baseEvent
	writer corebgp.UpdateMessageWriter
}

type onUpdateEvent struct {
	baseEvent
	update []byte
}

type onCloseEvent struct {
	baseEvent
}

func (p *plugin) GetCapabilities(peer corebgp.PeerConfig) []corebgp.Capability {
	p.event <- getCapsEvent{
		baseEvent: baseEvent{
			t: time.Now(),
			c: peer,
		},
	}
	return p.caps
}

func (p *plugin) OnOpenMessage(peer corebgp.PeerConfig, routerID net.IP,
	capabilities []corebgp.Capability) *corebgp.Notification {
	p.event <- onOpenEvent{
		baseEvent: baseEvent{
			t: time.Now(),
			c: peer,
		},
		routerID: routerID,
		caps:     capabilities,
	}
	return p.openNotification
}

func (p *plugin) OnEstablished(peer corebgp.PeerConfig,
	writer corebgp.UpdateMessageWriter) corebgp.UpdateMessageHandler {
	p.event <- onEstablishedEvent{
		baseEvent: baseEvent{
			t: time.Now(),
			c: peer,
		},
		writer: writer,
	}
	return p.updateMessageHandler
}

func (p *plugin) OnClose(peer corebgp.PeerConfig) {
	p.event <- onCloseEvent{
		baseEvent: baseEvent{
			t: time.Now(),
			c: peer,
		},
	}
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

func verifyPeerConfig(t *testing.T, event pluginEvent, config corebgp.PeerConfig) {
	if !reflect.DeepEqual(event.peer(), config) {
		t.Fatalf("unexpected peer: %v", event.peer())
	}
}

// TestCleanBGPSession exercises all plugin event handlers for a clean
// (no errors/notifications) BGP session w/BIRD. OPEN message negotiation is
// expected to succeed and UPDATE messages should flow.
func TestCleanBGPSession(t *testing.T) {
	// disable BGP session on BIRD side
	birdControl(t, "disable corebgp")

	eventCh := make(chan pluginEvent, 1000)
	onUpdateFn := func(peer corebgp.PeerConfig, update []byte) *corebgp.Notification {
		eventCh <- onUpdateEvent{
			baseEvent: baseEvent{
				t: time.Now(),
				c: peer,
			},
			update: update,
		}
		return nil
	}

	p := &plugin{
		caps: []corebgp.Capability{
			newMPCap(1, 1), // ipv4 unicast
			newMPCap(2, 1), // ipv6 unicast
		},
		openNotification:     nil,
		updateMessageHandler: onUpdateFn,
		event:                eventCh,
	}

	server, err := corebgp.NewServer(net.ParseIP(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		LocalAddress:  net.ParseIP(myAddress),
		RemoteAddress: net.ParseIP(birdAddress),
		RemoteAS:      birdAS,
		LocalAS:       myAS,
	}

	err = server.AddPeer(pc, p)
	if err != nil {
		t.Fatalf("error adding peer: %v", err)
	}

	// enable BGP session on BIRD side
	birdControl(t, "enable corebgp")

	lis, err := net.Listen("tcp", net.JoinHostPort(myAddress, "179"))
	if err != nil {
		t.Fatalf("error constructing listener: %v", err)
	}
	defer lis.Close()
	go server.Serve([]net.Listener{lis}) // nolint: errcheck
	defer server.Close()

	// verify GetCapabilities
	event := <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok := event.(getCapsEvent)
	if !ok {
		t.Fatal("not get caps event")
	}

	// verify OnOpenMessage
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	onOpen, ok := event.(onOpenEvent)
	if !ok {
		t.Fatal("not on open event")
	}
	if !onOpen.routerID.Equal(net.ParseIP(birdAddress)) {
		t.Errorf("expected router ID %s, got: %s", birdAddress,
			onOpen.routerID)
	}
	if len(onOpen.caps) < 2 {
		t.Errorf("expected at least 2 caps in open message, got: %d",
			len(onOpen.caps))
	}
	for _, capA := range p.caps {
		found := false
		for _, capB := range onOpen.caps {
			if reflect.DeepEqual(capA, capB) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("capability not found in peer's open message: %v",
				capA)
		}
	}

	// verify OnEstablished
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	oe, ok := event.(onEstablishedEvent)
	if !ok {
		t.Fatal("not on established event")
	}
	// send UPDATE to BIRD
	outboundUpdate := []byte{
		0x00, 0x00, // withdrawn routes length
		0x00, 0x14, // total path attribute length
		0x40, 0x01, 0x01, 0x00, // origin igp
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, // as_path 65001
		0x40, 0x03, 0x04, 0xc0, 0x00, 0x02, 0x01, // next_hop 192.0.2.1
		0x10, 0x0a, 0x00, // nlri 10.0.0.0/16
	}
	err = oe.writer.WriteUpdate(outboundUpdate)
	if err != nil {
		t.Fatalf("got error while sending update: %v", err)
	}

	// expect UPDATE containing 10.0.0.0/8
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	ou, ok := event.(onUpdateEvent)
	if !ok {
		t.Fatal("not on update event")
	}
	want := []byte{
		0x00, 0x00, // withdrawn routes length
		0x00, 0x14, // total path attribute length
		0x40, 0x01, 0x01, 0x00, // origin igp
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xea, // as_path 65002
		0x40, 0x03, 0x04, 0xc0, 0x00, 0x02, 0x02, // next_hop 192.0.2.2
		0x08, 0x0a, // nlri 10.0.0.0/8
	}
	if !bytes.Equal(want, ou.update) {
		t.Errorf("expected %s for IPv4 UPDATE, got: %v", want, ou.update)
	}

	// expect IPv4 End of RIB marker
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	ou, ok = event.(onUpdateEvent)
	if !ok {
		t.Fatal("not on update event")
	}
	want = []byte{0, 0, 0, 0}
	if !bytes.Equal(want, ou.update) {
		t.Errorf("expected %s for IPv4 EoR, got: %v", want, ou.update)
	}

	// expect IPv6 End of RIB Marker
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	ou, ok = event.(onUpdateEvent)
	if !ok {
		t.Fatal("not on update event")
	}
	// https://tools.ietf.org/html/rfc4724#section-2
	// An UPDATE message with no reachable Network Layer Reachability
	// Information (NLRI) and empty withdrawn NLRI is specified as the End-
	// of-RIB marker that can be used by a BGP speaker to indicate to its
	// peer the completion of the initial routing update after the session
	// is established.  For the IPv4 unicast address family, the End-of-RIB
	// marker is an UPDATE message with the minimum length [BGP-4].  For any
	// other address family, it is an UPDATE message that contains only the
	// MP_UNREACH_NLRI attribute [BGP-MP] with no withdrawn routes for that
	// <AFI, SAFI>.
	want = []byte{
		0x00, 0x00, // withdrawn routes length
		0x00, 0x06, // path attribute length
		0x80, 0x0f, 0x03, 0x00, 0x02, 0x01, // path attribute mp unreach nlri
	}
	if !bytes.Equal(want, ou.update) {
		t.Errorf("expected %v for IPv6 EoR, got: %v", want, ou.update)
	}

	// verify route seen by BIRD
	//
	/*
		bird> show route all 10.0.0.0/16
		Table master4:
		10.0.0.0/16          unicast [corebgp 21:53:24.644] ! (100) [AS65001i]
			via 192.0.2.1 on eth0
			Type: BGP univ
			BGP.origin: IGP
			BGP.as_path: 65001
			BGP.next_hop: 192.0.2.1
			BGP.local_pref: 100
	*/
	output := birdControl(t, "show route all 10.0.0.0/16")
	substrings := []string{
		"10.0.0.0/16",
		"corebgp",
		"BGP.origin: IGP",
		"BGP.as_path: 65001",
		"BGP.next_hop: 192.0.2.1",
		"BGP.local_pref: 100",
	}
	for _, sub := range substrings {
		if !strings.Contains(output, sub) {
			t.Errorf("expected substring '%s' in '%s'", sub, output)
		}
	}

	// shutdown bird
	birdControl(t, "disable corebgp")

	// verify OnClose
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok = event.(onCloseEvent)
	if !ok {
		t.Fatal("not on close event")
	}
}

// TestNotificationSentOnOpen exercises the OnOpenMessage() handler and returns
// a non-nil NOTIFICATION message to be sent to BIRD. We expect BIRD to receive
// the NOTIFICATION and enter an error state for the corebgp peer.
func TestNotificationSentOnOpen(t *testing.T) {
	// disable BGP session on BIRD side
	birdControl(t, "disable corebgp")

	eventCh := make(chan pluginEvent, 1000)
	notification := &corebgp.Notification{
		Code: corebgp.NotifCodeOpenMessageErr,
		Data: []byte{},
	}

	p := &plugin{
		caps: []corebgp.Capability{
			newMPCap(1, 1), // ipv4 unicast
			newMPCap(2, 1), // ipv6 unicast
		},
		openNotification:     notification,
		updateMessageHandler: nil,
		event:                eventCh,
	}

	server, err := corebgp.NewServer(net.ParseIP(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		LocalAddress:  net.ParseIP(myAddress),
		RemoteAddress: net.ParseIP(birdAddress),
		RemoteAS:      birdAS,
		LocalAS:       myAS,
	}

	err = server.AddPeer(pc, p)
	if err != nil {
		t.Fatalf("error adding peer: %v", err)
	}

	// enable BGP session on BIRD side
	birdControl(t, "enable corebgp")

	lis, err := net.Listen("tcp", net.JoinHostPort(myAddress, "179"))
	if err != nil {
		t.Fatalf("error constructing listener: %v", err)
	}
	defer lis.Close()
	go server.Serve([]net.Listener{lis}) // nolint: errcheck
	defer server.Close()

	// expect get caps event
	event := <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok := event.(getCapsEvent)
	if !ok {
		t.Fatal("not get caps event")
	}

	event = <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok = event.(onOpenEvent)
	if !ok {
		t.Fatal("not on open event")
	}

	// verify BIRD received the notification
	//
	/*
		bird> show protocols corebgp
		Name       Proto      Table      State  Since         Info
		corebgp    BGP        ---        start  22:39:46.063  Idle          Received: Invalid OPEN message
	*/
	output := birdControl(t, "show protocols corebgp")
	invalidOpen := "Received: Invalid OPEN message"
	if !strings.Contains(output, invalidOpen) {
		t.Fatalf("expected substring '%s' in '%s'", invalidOpen, output)
	}
}

// TestNotificationSentOnUpdate exercises the UpdateMessageHandler and returns a
// non-nil NOTIFICATION message to be sent to BIRD. We expect BIRD to receive
// the NOTIFICATION and enter an error state for the corebgp peer.
func TestNotificationSentOnUpdate(t *testing.T) {
	// disable BGP session on BIRD side
	birdControl(t, "disable corebgp")

	eventCh := make(chan pluginEvent, 1000)
	notification := &corebgp.Notification{
		Code: corebgp.NotifCodeUpdateMessageErr,
		Data: []byte{},
	}
	onUpdateFn := func(peer corebgp.PeerConfig, update []byte) *corebgp.Notification {
		eventCh <- onUpdateEvent{
			baseEvent: baseEvent{
				t: time.Now(),
				c: peer,
			},
			update: update,
		}
		return notification
	}
	p := &plugin{
		caps: []corebgp.Capability{
			newMPCap(1, 1), // ipv4 unicast
			newMPCap(2, 1), // ipv6 unicast
		},
		openNotification:     nil,
		updateMessageHandler: onUpdateFn,
		event:                eventCh,
	}

	server, err := corebgp.NewServer(net.ParseIP(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		LocalAddress:  net.ParseIP(myAddress),
		RemoteAddress: net.ParseIP(birdAddress),
		RemoteAS:      birdAS,
		LocalAS:       myAS,
	}

	err = server.AddPeer(pc, p)
	if err != nil {
		t.Fatalf("error adding peer: %v", err)
	}

	// enable BGP session on BIRD side
	birdControl(t, "enable corebgp")

	lis, err := net.Listen("tcp", net.JoinHostPort(myAddress, "179"))
	if err != nil {
		t.Fatalf("error constructing listener: %v", err)
	}
	defer lis.Close()
	go server.Serve([]net.Listener{lis}) // nolint: errcheck
	defer server.Close()

	// expect get caps event
	event := <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok := event.(getCapsEvent)
	if !ok {
		t.Fatal("not get caps event")
	}

	// expect on open event
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok = event.(onOpenEvent)
	if !ok {
		t.Fatal("not on open event")
	}

	// expect on established event
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok = event.(onEstablishedEvent)
	if !ok {
		t.Fatal("not on established event")
	}

	// expect on update event
	event = <-p.event
	verifyPeerConfig(t, event, pc)
	_, ok = event.(onUpdateEvent)
	if !ok {
		t.Fatal("not on update event")
	}

	// verify BIRD received the notification
	//
	/*
		bird> show protocols corebgp
		Name       Proto      Table      State  Since         Info
		corebgp    BGP        ---        start  22:57:50.627  Idle          Received: Invalid UPDATE message
	*/
	output := birdControl(t, "show protocols corebgp")
	invalidUpdate := "Received: Invalid UPDATE message"
	if !strings.Contains(output, invalidUpdate) {
		t.Fatalf("expected substring '%s' in '%s'", invalidUpdate, output)
	}
}

func TestBIRDControl(t *testing.T) {
	birdControl(t, "show protocols all")
}

const (
	controlSocket = "/run/bird/bird.ctl"
)

var (
	birdReadyPrefix = regexp.MustCompile(`^0001 BIRD.*ready.`)
	birdLinePrefix  = regexp.MustCompile(`^[0-9]{4}[ \-]`)
)

// birdControl connects to the BIRD unix socket, runs a command, and returns the
// output.
//
// documentation on BIRD's unix socket: https://bird.network.cz/?get_doc&v=20&f=prog-2.html#ss2.9
//
// sample birdctl output:
/*
0001 BIRD v2.0.7 ready.
2002-Name       Proto      Table      State  Since         Info
1002-device1    Device     ---        up     21:35:14.093
1006-
1002-direct1    Direct     ---        down   21:35:14.093
1006-  Channel ipv4
     State:          DOWN
     Table:          master4
     Preference:     240
     Input filter:   ACCEPT
     Output filter:  REJECT
   Channel ipv6
     State:          DOWN
     Table:          master6
     Preference:     240
     Input filter:   ACCEPT
     Output filter:  REJECT
   bird_test.go:82:
1002-kernel1    Kernel     master4    up     21:35:14.093
1006-  Channel ipv4
     State:          UP
     Table:          master4
     Preference:     10
     Input filter:   ACCEPT
     Output filter:  ACCEPT
     Routes:         0 imported, 0 exported, 0 preferred
     Route change stats:     received   rejected   filtered    ignored   accepted
       Import updates:              0          0          0          0          0
       Import withdraws:            0          0        ---          0          0
       Export updates:              0          0          0        ---          0
       Export withdraws:            0        ---        ---        ---          0
   bird_test.go:82:
1002-kernel2    Kernel     master6    up     21:35:14.093
1006-  Channel ipv6
     State:          UP
     Table:          master6
     Preference:     10
     Input filter:   ACCEPT
     Output filter:  ACCEPT
     Routes:         0 imported, 0 exported, 0 preferred
     Route change stats:     received   rejected   filtered    ignored   accepted
       Import updates:              0          0          0          0          0
       Import withdraws:            0          0        ---          0          0
       Export updates:              0          0          0        ---          0
       Export withdraws:            0        ---        ---        ---          0
   bird_test.go:82:
1002-static1    Static     master4    up     21:35:14.093
1006-  Channel ipv4
     State:          UP
     Table:          master4
     Preference:     200
     Input filter:   ACCEPT
     Output filter:  REJECT
     Routes:         0 imported, 0 exported, 0 preferred
     Route change stats:     received   rejected   filtered    ignored   accepted
       Import updates:              0          0          0          0          0
       Import withdraws:            0          0        ---          0          0
       Export updates:              0          0          0        ---          0
       Export withdraws:            0        ---        ---        ---          0
   bird_test.go:82:
1002-corebgp    BGP        ---        start  21:35:14.093  Active        Socket: Connection refused
1006-  Description:    corebgp
   BGP state:          Active
     Neighbor address: 192.0.2.1
     Neighbor AS:      65001
     Local AS:         65002
     Connect delay:    2.979/5
     Last error:       Socket: Connection refused
   Channel ipv4
     State:          DOWN
     Table:          master4
     Preference:     100
     Input filter:   ACCEPT
     Output filter:  (unnamed)
   Channel ipv6
     State:          DOWN
     Table:          master6
     Preference:     100
     Input filter:   ACCEPT
     Output filter:  (unnamed)
   bird_test.go:82:
0000
*/
func birdControl(t *testing.T, command string) string {
	c, err := net.Dial("unix", controlSocket)
	if err != nil {
		t.Fatalf("error dialing UDS: %v", err)
	}
	defer c.Close()

	_, err = c.Write([]byte(fmt.Sprintf("%s\r\n", command)))
	if err != nil {
		t.Fatalf("error writing to UDS: %v", err)
	}

	var out strings.Builder
	scanner := bufio.NewScanner(c)
	first := true
	for scanner.Scan() {
		b := scanner.Bytes()
		if first {
			// BIRD spits out '0001 BIRD v2.0.7 ready.' upon connecting
			if !birdReadyPrefix.Match(b) {
				t.Fatalf("unexpected first line back from BIRD: %s", b)
			}
			first = false
			continue
		}
		if birdLinePrefix.Match(b) {
			if bytes.Equal(b[:5], []byte("0000 ")) {
				// done
				break
			}
			b = b[5:]
		}
		out.Write(b)
		out.WriteByte('\n')
	}

	return out.String()
}
