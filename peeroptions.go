package corebgp

import (
	"errors"
	"time"
)

type peerOptions struct {
	holdTime         time.Duration
	idleHoldTime     time.Duration
	connectRetryTime time.Duration
	passive          bool
}

func (p *peerOptions) valid() error {
	if p.holdTime < time.Second*3 {
		return errors.New("hold time must be >= 3 seconds")
	}
	return nil
}

type PeerOption interface {
	apply(*peerOptions)
}

const (
	// DefaultHoldTime is the default hold down time.
	DefaultHoldTime = time.Second * 90
	// DefaultIdleHoldTime is the default idle state hold time for a peer.
	DefaultIdleHoldTime = time.Second * 5
	// DefaultConnectRetryTime is the default maximum time spent waiting for an
	// outbound dial to connect.
	//
	// https://tools.ietf.org/html/rfc4271#section-8.2.2
	// The exact value of the ConnectRetryTimer is a local matter, but it
	// SHOULD be sufficiently large to allow TCP initialization.
	DefaultConnectRetryTime = time.Second * 5
)

func defaultPeerOptions() *peerOptions {
	return &peerOptions{
		holdTime:         DefaultHoldTime,
		idleHoldTime:     DefaultIdleHoldTime,
		connectRetryTime: DefaultConnectRetryTime,
		passive:          false,
	}
}

type funcPeerOption struct {
	fn func(*peerOptions)
}

func (f *funcPeerOption) apply(p *peerOptions) {
	f.fn(p)
}

func newFuncPeerOption(f func(*peerOptions)) *funcPeerOption {
	return &funcPeerOption{
		fn: f,
	}
}

// WithPassive returns a PeerOption that sets a Peer to passive mode. In passive
// mode a peer will not dial out and will only accept incoming connections.
func WithPassive() PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.passive = true
	})
}

// WithIdleHoldTime returns a PeerOption that sets the idle hold time for a
// peer. Idle hold time controls how quickly a peer can oscillate from idle to
// the connect state.
func WithIdleHoldTime(t time.Duration) PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.idleHoldTime = t
	})
}

// WithConnectRetryTime returns a PeerOption that sets the connect retry time
// for a peer.
func WithConnectRetryTime(t time.Duration) PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.connectRetryTime = t
	})
}
