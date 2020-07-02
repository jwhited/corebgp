package corebgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// Server is a BGP server that manages peers.
type Server struct {
	mu            sync.Mutex
	id            uint32
	peers         map[string]*peer
	serving       bool
	doneServingCh chan struct{}
	closeCh       chan struct{}
	closeOnce     sync.Once
}

// NewServer creates a new Server.
func NewServer(routerID net.IP) (*Server, error) {
	v4 := routerID.To4()
	if v4 == nil {
		return nil, errors.New("invalid router ID")
	}

	s := &Server{
		mu:            sync.Mutex{},
		id:            binary.BigEndian.Uint32(v4),
		peers:         make(map[string]*peer),
		doneServingCh: make(chan struct{}),
		closeCh:       make(chan struct{}),
	}
	return s, nil
}

var (
	ErrServerClosed = errors.New("server closed")
)

// Serve starts all peers' FSMs, starts handling incoming connections if a
// non-nil listener is provided, and then blocks. Serve returns ErrServerClosed
// upon Close() or a listener error if one occurs.
func (s *Server) Serve(lis net.Listener) error {
	s.mu.Lock()
	// check if server has been closed
	select {
	case <-s.doneServingCh:
		s.mu.Unlock()
		return ErrServerClosed
	case <-s.closeCh:
		s.mu.Unlock()
		return ErrServerClosed
	default:
	}

	// set serving state and enable peers
	s.serving = true
	for _, peer := range s.peers {
		peer.start()
	}
	s.mu.Unlock()

	defer func() {
		// disable peers and set serving state before returning
		s.mu.Lock()
		for _, peer := range s.peers {
			peer.stop()
		}
		s.serving = false
		close(s.doneServingCh)
		s.mu.Unlock()
	}()

	lisErrCh := make(chan error)
	if lis != nil {
		go func() {
			for {
				conn, err := lis.Accept()
				if err != nil {
					lisErrCh <- err
					return
				}
				h, _, err := net.SplitHostPort(conn.RemoteAddr().String())
				if err != nil {
					conn.Close()
					continue
				}
				s.mu.Lock()
				p, exists := s.peers[h]
				if !exists {
					conn.Close()
					s.mu.Unlock()
					continue
				}
				p.incomingConnection(conn)
				s.mu.Unlock()
			}
		}()
	}

	select {
	case <-s.closeCh:
		if lis != nil {
			lis.Close()
			<-lisErrCh
		}
		return ErrServerClosed
	case err := <-lisErrCh:
		return fmt.Errorf("listener error: %v", err)
	}
}

// Close stops the Server. An instance of a stopped Server cannot be re-used.
func (s *Server) Close() {
	s.mu.Lock()
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	if !s.serving {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	<-s.doneServingCh
}

// PeerConfig is the required configuration for a Peer.
type PeerConfig struct {
	IP       net.IP
	LocalAS  uint32
	RemoteAS uint32
}

const (
	DefaultHoldTime     = time.Second * 90
	DefaultIdleHoldTime = time.Second * 5
)

func defaultPeerOptions() *peerOptions {
	return &peerOptions{
		holdTime:     DefaultHoldTime,
		idleHoldTime: DefaultIdleHoldTime,
		passive:      false,
	}
}

type PeerOption interface {
	apply(*peerOptions)
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

// Passive returns a PeerOption that sets a Peer to passive mode. In passive
// mode a peer will not dial out and will only accept incoming connections.
func Passive() PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.passive = true
	})
}

// IdleHoldTime returns a PeerOption that sets the idle hold time for a peer.
// Idle hold time controls how quickly a peer can oscillate from idle to the
// connect state.
func IdleHoldTime(t time.Duration) PeerOption {
	return newFuncPeerOption(func(o *peerOptions) {
		o.idleHoldTime = t
	})
}

type peerOptions struct {
	holdTime     time.Duration
	idleHoldTime time.Duration
	passive      bool
}

func (p *PeerConfig) validate() error {
	if p.IP.To4() == nil && p.IP.To16() == nil {
		return errors.New("invalid peer IP")
	}
	// https://tools.ietf.org/html/rfc7607
	if p.LocalAS == 0 || p.RemoteAS == 0 {
		return errors.New("AS must be > 0")
	}
	return nil
}

// AddPeer adds a peer to the Server to be handled with the provided Plugin and
// PeerOptions.
func (s *Server) AddPeer(config *PeerConfig, plugin Plugin,
	opts ...PeerOption) error {
	err := config.validate()
	if err != nil {
		return fmt.Errorf("peer config invalid: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.peers[config.IP.String()]
	if exists {
		return errors.New("peer already exists")
	}
	o := defaultPeerOptions()
	for _, opt := range opts {
		opt.apply(o)
	}
	p := newPeer(config, s.id, plugin, o)
	if s.serving {
		p.start()
	}
	s.peers[p.config.IP.String()] = p
	return nil
}

// DeletePeer deletes a peer from the Server.
func (s *Server) DeletePeer(ip net.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.peers[ip.String()]
	if !exists {
		return errors.New("peer does not exist")
	}
	p.stop()
	delete(s.peers, ip.String())
	return nil
}

// TODO: Get/ListPeer

// no need for Enable/DisablePeer complexity, just use Add/DeletePeer.
