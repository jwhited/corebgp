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
	caps []corebgp.Capability
}

type onEstablishedEvent struct {
	baseEvent
	writer corebgp.UpdateMessageWriter
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

func (p *plugin) OnOpenMessage(peer corebgp.PeerConfig,
	capabilities []corebgp.Capability) *corebgp.Notification {
	p.event <- onOpenEvent{
		baseEvent: baseEvent{
			t: time.Now(),
			c: peer,
		},
		caps: capabilities,
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

func TestBGP(t *testing.T) {
	// disable BGP session on BIRD side
	birdControl(t, "disable corebgp")

	p := &plugin{
		caps: []corebgp.Capability{
			newMPCap(1, 1), // ipv4 unicast
			newMPCap(2, 1), // ipv6 unicast
		},
		openNotification:     nil,
		updateMessageHandler: nil,
		event:                make(chan pluginEvent, 1000),
	}

	server, err := corebgp.NewServer(net.ParseIP(myAddress))
	if err != nil {
		t.Fatalf("error constructing server: %v", err)
	}

	pc := corebgp.PeerConfig{
		IP:       net.ParseIP(birdAddress),
		RemoteAS: birdAS,
		LocalAS:  myAS,
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

	serveErrCh := make(chan error)
	go func() {
		serveErrCh <- server.Serve(lis)
	}()

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
	if len(onOpen.caps) < 2 {
		t.Fatalf("expected at least 2 caps in open message, got: %d",
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
	_, ok = event.(onEstablishedEvent)
	if !ok {
		t.Fatal("not on established event")
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
