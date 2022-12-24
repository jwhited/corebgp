package corebgp

import (
	"errors"
	"net/netip"
	"syscall"
	"time"
)

type peerOptions struct {
	holdTime         time.Duration
	idleHoldTime     time.Duration
	connectRetryTime time.Duration
	port             int
	passive          bool
	dialerControlFn  func(network, address string, c syscall.RawConn) error
	localAddress     netip.Addr
}

func (p peerOptions) validate() error {
	if p.holdTime < time.Second*3 {
		return errors.New("hold time must be >= 3 seconds")
	}
	if p.port < 1 || p.port > 65535 {
		return errors.New("port must be between 1 and 65535")
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
	// DefaultPort is the default TCP port for a peer.
	DefaultPort = 179
)

func defaultPeerOptions() peerOptions {
	return peerOptions{
		holdTime:         DefaultHoldTime,
		idleHoldTime:     DefaultIdleHoldTime,
		connectRetryTime: DefaultConnectRetryTime,
		port:             DefaultPort,
		passive:          false,
		localAddress:     netip.Addr{},
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

// WithPort returns a PeerOption that sets the TCP port for a peer.
func WithPort(p int) PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.port = p
	})
}

// WithDialerControl returns a PeerOption that sets the outbound net.Dialer
// Control field. This is commonly used to set socket options, e.g. ip TTL, tcp
// md5, tcp_nodelay, etc...
func WithDialerControl(fn func(network, address string,
	c syscall.RawConn) error) PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.dialerControlFn = fn
	})
}

// WithLocalAddress returns a PeerOption that specifies the source address to
// use when dialing outbound, and to verify as a destination for inbound
// connections. Without this PeerOption corebgp behaves loosely, accepting
// inbound connections regardless of the destination address, and falling back
// on the OS for outbound source address selection.
func WithLocalAddress(localAddress netip.Addr) PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.localAddress = localAddress
	})
}
