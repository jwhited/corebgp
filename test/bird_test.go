//go:build integration

package test

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/netip"
	"reflect"
	"regexp"
	"strings"
	"syscall"
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
	routerID netip.Addr
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

func (p *plugin) OnOpenMessage(peer corebgp.PeerConfig, routerID netip.Addr,
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

func (p *plugin) wantGetCapsEvent(t *testing.T, pc corebgp.PeerConfig) getCapsEvent {
	got := <-p.event
	want, ok := got.(getCapsEvent)
	if !ok {
		t.Fatalf("want: getCapsEvent, got: %s", reflect.TypeOf(got))
	}
	verifyPeerConfig(t, want, pc)
	return want
}

func (p *plugin) wantOnOpenEvent(t *testing.T, pc corebgp.PeerConfig) onOpenEvent {
	got := <-p.event
	want, ok := got.(onOpenEvent)
	if !ok {
		t.Fatalf("want: onOpenEvent, got: %s", reflect.TypeOf(got))
	}
	verifyPeerConfig(t, want, pc)
	return want
}

func (p *plugin) wantOnEstablishedEvent(t *testing.T, pc corebgp.PeerConfig) onEstablishedEvent {
	got := <-p.event
	want, ok := got.(onEstablishedEvent)
	if !ok {
		t.Fatalf("want: onEstablishedEvent, got: %s", reflect.TypeOf(got))
	}
	verifyPeerConfig(t, want, pc)
	return want
}

func (p *plugin) wantOnUpdateEvent(t *testing.T, pc corebgp.PeerConfig) onUpdateEvent {
	got := <-p.event
	want, ok := got.(onUpdateEvent)
	if !ok {
		t.Fatalf("want: onUpdateEvent, got: %s", reflect.TypeOf(got))
	}
	verifyPeerConfig(t, want, pc)
	return want
}

func (p *plugin) wantOnCloseEvent(t *testing.T, pc corebgp.PeerConfig) onCloseEvent {
	got := <-p.event
	want, ok := got.(onCloseEvent)
	if !ok {
		t.Fatalf("want: onCloseEvent, got: %s", reflect.TypeOf(got))
	}
	verifyPeerConfig(t, want, pc)
	return want
}

func verifyPeerConfig(t *testing.T, event pluginEvent, config corebgp.PeerConfig) {
	if !reflect.DeepEqual(event.peer(), config) {
		t.Fatalf("unexpected peer: %v", event.peer())
	}
}

const configPath = "/etc/bird/bird.conf"

func loadBIRDConfig(t *testing.T, config []byte) {
	birdControl(t, "disable all")
	err := ioutil.WriteFile(configPath, config, 0644)
	if err != nil {
		t.Fatalf("error writing bird config: %v", err)
	}
	if !strings.Contains(
		birdControl(t, "configure check"),
		"Configuration OK") {
		t.Fatal("configure check failed")
	}
	if !strings.Contains(
		birdControl(t, fmt.Sprintf(`configure "%s"`, configPath)),
		"Reconfigured") {
		t.Fatal("failed to reconfigure bird")
	}
	birdControl(t, "enable all")
}

func baseBIRDConfig(plus []byte) []byte {
	return append([]byte(`
router id 192.0.2.2;
protocol device {
}
protocol kernel {
	ipv4 {
	      table master4;
	      import all;
	      export all;
	};
}
`), plus...)
}

// TestCleanBGPSession exercises all plugin event handlers for a clean
// (no errors/notifications) BGP session w/BIRD. OPEN message negotiation is
// expected to succeed and UPDATE messages should flow.
func TestCleanBGPSession(t *testing.T) {
	loadBIRDConfig(t, baseBIRDConfig([]byte(`
protocol static {
	ipv4;
	route 10.0.0.0/8 via "eth0";
}
protocol bgp corebgp {
	description "corebgp";
	local 192.0.2.2 as 65002;
	neighbor 192.0.2.1 as 65001;
	hold time 90;
	ipv4 {
		import all;
		export where source ~ [ RTS_STATIC, RTS_BGP ];
	};
	ipv6 {
		import all;
		export where source ~ [ RTS_STATIC, RTS_BGP ];
	};
}
`)))
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
			corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV4, corebgp.SAFI_UNICAST),
			corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV6, corebgp.SAFI_UNICAST),
		},
		openNotification:     nil,
		updateMessageHandler: onUpdateFn,
		event:                eventCh,
	}

	server, err := corebgp.NewServer(netip.MustParseAddr(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		RemoteAddress: netip.MustParseAddr(birdAddress),
		RemoteAS:      birdAS,
		LocalAS:       myAS,
	}

	err = server.AddPeer(pc, p, corebgp.WithLocalAddress(netip.MustParseAddr(myAddress)))
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
	p.wantGetCapsEvent(t, pc)

	// verify OnOpenMessage
	onOpen := p.wantOnOpenEvent(t, pc)
	if onOpen.routerID != netip.MustParseAddr(birdAddress) {
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
	oe := p.wantOnEstablishedEvent(t, pc)
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
	ou := p.wantOnUpdateEvent(t, pc)
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
	ou = p.wantOnUpdateEvent(t, pc)
	want = []byte{0, 0, 0, 0}
	if !bytes.Equal(want, ou.update) {
		t.Errorf("expected %s for IPv4 EoR, got: %v", want, ou.update)
	}

	// expect IPv6 End of RIB Marker
	ou = p.wantOnUpdateEvent(t, pc)
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
	p.wantOnCloseEvent(t, pc)
}

// TestNotificationSentOnOpen exercises the OnOpenMessage() handler and returns
// a non-nil NOTIFICATION message to be sent to BIRD. We expect BIRD to receive
// the NOTIFICATION and enter an error state for the corebgp peer.
func TestNotificationSentOnOpen(t *testing.T) {
	loadBIRDConfig(t, baseBIRDConfig([]byte(`
protocol bgp corebgp {
	description "corebgp";
	local 192.0.2.2 as 65002;
	neighbor 192.0.2.1 as 65001;
	hold time 90;
	ipv4 {
		import all;
		export none;
	};
}
`)))
	// disable BGP session on BIRD side
	birdControl(t, "disable corebgp")

	eventCh := make(chan pluginEvent, 1000)
	notification := &corebgp.Notification{
		Code: corebgp.NOTIF_CODE_OPEN_MESSAGE_ERR,
		Data: []byte{},
	}

	p := &plugin{
		caps: []corebgp.Capability{
			corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV4, corebgp.SAFI_UNICAST),
		},
		openNotification:     notification,
		updateMessageHandler: nil,
		event:                eventCh,
	}

	server, err := corebgp.NewServer(netip.MustParseAddr(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		RemoteAddress: netip.MustParseAddr(birdAddress),
		RemoteAS:      birdAS,
		LocalAS:       myAS,
	}

	err = server.AddPeer(pc, p, corebgp.WithLocalAddress(netip.MustParseAddr(myAddress)))
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
	p.wantGetCapsEvent(t, pc)

	p.wantOnOpenEvent(t, pc)

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
	loadBIRDConfig(t, baseBIRDConfig([]byte(`
protocol bgp corebgp {
	description "corebgp";
	local 192.0.2.2 as 65002;
	neighbor 192.0.2.1 as 65001;
	hold time 90;
	ipv4 {
		import all;
		export none;
	};
}
`)))
	// disable BGP session on BIRD side
	birdControl(t, "disable corebgp")

	eventCh := make(chan pluginEvent, 1000)
	notification := &corebgp.Notification{
		Code: corebgp.NOTIF_CODE_UPDATE_MESSAGE_ERR,
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
			corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV4, corebgp.SAFI_UNICAST),
		},
		openNotification:     nil,
		updateMessageHandler: onUpdateFn,
		event:                eventCh,
	}

	server, err := corebgp.NewServer(netip.MustParseAddr(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		RemoteAddress: netip.MustParseAddr(birdAddress),
		RemoteAS:      birdAS,
		LocalAS:       myAS,
	}

	err = server.AddPeer(pc, p, corebgp.WithLocalAddress(netip.MustParseAddr(myAddress)))
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
	p.wantGetCapsEvent(t, pc)

	// expect on open event
	p.wantOnOpenEvent(t, pc)

	// expect on established event
	p.wantOnEstablishedEvent(t, pc)

	// expect on update event
	p.wantOnUpdateEvent(t, pc)

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

// TestWithDialerControl exercises the WithDialerControl PeerOption by setting
// a TCP MD5 signature on the dialing socket.
func TestWithDialerControl(t *testing.T) {
	loadBIRDConfig(t, baseBIRDConfig([]byte(`
protocol bgp corebgp {
	description "corebgp";
	password "password";
	local 192.0.2.2 as 65002;
	neighbor 192.0.2.1 as 65001;
	hold time 90;
	ipv4 {
		import all;
		export none;
	};
}
`)))
	// disable BGP session on BIRD side
	birdControl(t, "disable corebgp")

	eventCh := make(chan pluginEvent, 1000)
	p := &plugin{
		caps: []corebgp.Capability{
			corebgp.NewMPExtensionsCapability(corebgp.AFI_IPV4, corebgp.SAFI_UNICAST),
		},
		updateMessageHandler: nil,
		event:                eventCh,
	}

	server, err := corebgp.NewServer(netip.MustParseAddr(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		RemoteAddress: netip.MustParseAddr(birdAddress),
		RemoteAS:      birdAS,
		LocalAS:       myAS,
	}

	err = server.AddPeer(pc, p, corebgp.WithLocalAddress(netip.MustParseAddr(myAddress)),
		corebgp.WithDialerControl(func(network, address string, c syscall.RawConn) error {
			var seterr error
			err := c.Control(func(fdPtr uintptr) {
				fd := int(fdPtr)
				seterr = corebgp.SetTCPMD5Signature(fd, pc.RemoteAddress,
					32, "password")
			})
			if err != nil {
				return err
			}
			return seterr
		}))
	if err != nil {
		t.Fatalf("error adding peer: %v", err)
	}

	// enable BGP session on BIRD side
	birdControl(t, "enable corebgp")

	// don't listen in order to ensure Dialer.Control is exercised
	go server.Serve(nil) // nolint: errcheck
	defer server.Close()

	// expect get caps event
	p.wantGetCapsEvent(t, pc)

	// expect on open event
	p.wantOnOpenEvent(t, pc)

	// expect on established event
	p.wantOnEstablishedEvent(t, pc)
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
			// Requests are commands encoded as a single line of text, replies
			// are sequences of lines starting with a four-digit code followed
			// by either a space (if it's the last line of the reply) or a minus
			// sign (when the reply is going to continue with the next line)
			if b[4] == ' ' {
				out.Write(b[5:]) // sometimes the last line contains text
				break
			}
			b = b[5:]
		}
		out.Write(b)
		out.WriteByte('\n')
	}

	return out.String()
}
