# CoreBGP

[![GoDev](https://img.shields.io/static/v1?label=godev&message=reference&color=00add8)](https://pkg.go.dev/github.com/jwhited/corebgp)

CoreBGP is a BGP library written in Go that implements the BGP FSM with an event-driven, pluggable model. It exposes an API that empowers the user to:
* send and validate OPEN message capabilities
* handle "important" state transitions
* handle incoming UPDATE messages
* send outgoing UPDATE messages

CoreBGP does not decode UPDATE messages (besides header validation), manage a routing table, or send its own UPDATE messages. These responsibilities are all passed down to the user. Therefore, the intended user is someone who wants that responsibility.

See this [blog post](https://www.jordanwhited.com/posts/corebgp-plugging-in-to-bgp/) for the background and reasoning behind the development of CoreBGP.

The primary building block of CoreBGP is a Plugin, defined by the following interface:
```go
// Plugin is a BGP peer plugin.
type Plugin interface {
	// GetCapabilities is fired when a peer's FSM is in the Connect state prior
	// to sending an Open message. The returned capabilities are included in the
	// Open message sent to the peer.
	GetCapabilities(peer PeerConfig) []Capability

	// OnOpenMessage is fired when an Open message is received from a peer
	// during the OpenSent state. Returning a non-nil Notification will cause it
	// to be sent to the peer and the FSM will transition to the Idle state.
	//
	// Per RFC5492 a BGP speaker should only send a Notification if a required
	// capability is missing; unknown or unsupported capabilities should be
	// ignored.
	OnOpenMessage(peer PeerConfig, capabilities []Capability) *Notification

	// OnEstablished is fired when a peer's FSM transitions to the Established
	// state. The returned UpdateMessageHandler will be fired when an Update
	// message is received from the peer.
	//
	// The provided writer can be used to send Update messages to the peer for
	// the lifetime of the FSM's current, established state. It should be
	// discarded once OnClose() fires.
	OnEstablished(peer PeerConfig, writer UpdateMessageWriter) UpdateMessageHandler

	// OnClose is fired when a peer's FSM transitions out of the Established
	// state.
	OnClose(peer PeerConfig)
}
```

Here's an example Plugin that logs when a peer enters/leaves an established state and when an UPDATE message is received:
```go
type plugin struct{}

func (p *plugin) GetCapabilities(c corebgp.PeerConfig) []corebgp.Capability {
	caps := make([]corebgp.Capability, 0)
	return caps
}

func (p *plugin) OnOpenMessage(peer corebgp.PeerConfig, capabilities []corebgp.Capability) *corebgp.Notification {
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
```

Plugins are attached to peers when they are added to the Server, which manages their lifetime:
``` go
routerID := net.ParseIP("192.0.2.1")
srv, err := corebgp.NewServer(routerID)
if err != nil {
    log.Fatalf("error constructing server: %v", err)
}
p := &plugin{}
err = srv.AddPeer(corebgp.PeerConfig{
    IP:       net.ParseIP("198.51.100.10"),
    LocalAS:  65001,
    RemoteAS: 65010,
}, p)
if err != nil {
    log.Fatalf("error adding peer: %v", err)
}
```

For more examples check out the [examples directory](https://github.com/jwhited/corebgp/tree/master/examples) and [pkg.go.dev](https://pkg.go.dev/github.com/jwhited/corebgp?tab=doc) for the complete API.