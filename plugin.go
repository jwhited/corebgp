package corebgp

// Plugin is a BGP peer plugin.
type Plugin interface {
	// GetCapabilities is fired when a peer's FSM is in the Connect state prior
	// to sending an Open message. The returned capabilities are included in the
	// Open message sent to the peer.
	GetCapabilities(peer *PeerConfig) []*Capability

	// OnOpenMessage is fired when an Open message is received from a peer
	// during the OpenSent state. Returning a non-nil Notification will cause it
	// to be sent to the peer and the FSM will transition to the Idle state.
	//
	// Per RFC5492 a BGP speaker should only send a Notification if a required
	// capability is missing; unknown or unsupported capabilities should be
	// ignored.
	OnOpenMessage(peer *PeerConfig, capabilities []*Capability) *Notification

	// OnEstablished is fired when a peer's FSM transitions to the Established
	// state. The returned UpdateMessageHandler will be fired when an Update
	// message is received from the peer.
	//
	// The provided writer can be used to send Update messages to the peer for
	// the lifetime of the FSM's current, established state. It should be
	// discarded once OnClose() fires.
	OnEstablished(peer *PeerConfig, writer UpdateMessageWriter) UpdateMessageHandler

	// OnClose is fired when a peer's FSM transitions out of the Established
	// state.
	OnClose(peer *PeerConfig)
}

// UpdateMessageHandler handles Update messages. If a non-nil Notification is
// returned it will be sent to the peer and the FSM will transition out of the
// Established state.
type UpdateMessageHandler func(peer *PeerConfig, updateMessage []byte) *Notification

type UpdateMessageWriter interface {
	// WriteUpdate sends an update message to the remote peer. An error is
	// returned if the write fails and/or the FSM is no longer in an established
	// state.
	WriteUpdate([]byte) error
}
