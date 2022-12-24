package corebgp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Server is a BGP server that manages peers.
type Server struct {
	mu    sync.Mutex
	id    uint32
	peers map[string]*peer

	// control channels & run state
	serving       bool
	doneServingCh chan struct{}
	closeCh       chan struct{}
	closeOnce     sync.Once
}

// NewServer creates a new Server.
func NewServer(routerID netip.Addr) (*Server, error) {
	if !routerID.Is4() {
		return nil, errors.New("invalid router ID")
	}

	s := &Server{
		mu:            sync.Mutex{},
		id:            binary.BigEndian.Uint32(routerID.AsSlice()),
		peers:         make(map[string]*peer),
		doneServingCh: make(chan struct{}),
		closeCh:       make(chan struct{}),
	}
	return s, nil
}

var (
	ErrServerClosed      = errors.New("server closed")
	ErrPeerNotExist      = errors.New("peer does not exist")
	ErrPeerAlreadyExists = errors.New("peer already exists")
)

func (s *Server) handleInboundConn(conn net.Conn) {
	h, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		conn.Close()
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.peers[h]
	if !exists {
		conn.Close()
		return
	}
	if p.options.localAddress.IsValid() {
		h, _, err = net.SplitHostPort(conn.LocalAddr().String())
		laddr, _ := netip.ParseAddr(h)
		if err != nil || p.options.localAddress != laddr {
			conn.Close()
			return
		}
	}
	p.incomingConnection(conn)
}

// Serve starts all peers' FSMs, starts handling incoming connections if a
// non-nil listener is provided, and then blocks. Serve returns ErrServerClosed
// upon Close() or a listener error if one occurs.
func (s *Server) Serve(listeners []net.Listener) error {
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
	lisWG := &sync.WaitGroup{}
	closingListeners := make(chan struct{})
	for _, lis := range listeners {
		lisWG.Add(1)
		go func(lis net.Listener) {
			defer lisWG.Done()
			for {
				conn, err := lis.Accept()
				if err != nil {
					select {
					case lisErrCh <- err:
					case <-closingListeners:
					}
					return
				}
				s.handleInboundConn(conn)
			}
		}(lis)
	}

	closeListeners := func() {
		close(closingListeners)
		for _, lis := range listeners {
			lis.Close()
		}
		lisWG.Wait()
	}

	select {
	case <-s.closeCh:
		closeListeners()
		return ErrServerClosed
	case err := <-lisErrCh:
		closeListeners()
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
	// RemoteAddress is the remote address of the peer.
	RemoteAddress netip.Addr

	// LocalAS is the local autonomous system number to populate in outbound
	// OPEN messages.
	LocalAS uint32

	// RemoteAS is the autonomous system number to expect in OPEN messages
	// from this peer.
	RemoteAS uint32
}

func (p PeerConfig) validate(opts peerOptions) error {
	if !opts.localAddress.IsValid() && p.RemoteAddress.IsValid() {
		return nil
	}
	localIsIPv4 := opts.localAddress.Is4()
	remoteIsIPv4 := p.RemoteAddress.Is4()
	if localIsIPv4 != remoteIsIPv4 {
		return errors.New("mixed address family peer address pair")
	}
	if !localIsIPv4 {
		if !opts.localAddress.Is6() || !p.RemoteAddress.Is6() {
			return errors.New("invalid peer address pair")
		}
	}
	// https://tools.ietf.org/html/rfc7607
	//
	// If a BGP speaker receives zero as the peer AS in an OPEN message, it
	// MUST abort the connection and send a NOTIFICATION with Error Code
	// "OPEN Message Error" and subcode "Bad Peer AS" (see Section 6 of
	// [RFC4271]).  A router MUST NOT initiate a connection claiming to be
	// AS 0.
	if p.LocalAS == 0 || p.RemoteAS == 0 {
		return errors.New("AS must be > 0")
	}
	return nil
}

// AddPeer adds a peer to the Server to be handled with the provided Plugin and
// PeerOptions.
func (s *Server) AddPeer(config PeerConfig, plugin Plugin,
	opts ...PeerOption) error {
	o := defaultPeerOptions()
	for _, opt := range opts {
		opt.apply(&o)
	}
	err := o.validate()
	if err != nil {
		return fmt.Errorf("invalid peer options: %v", err)
	}
	err = config.validate(o)
	if err != nil {
		return fmt.Errorf("peer config invalid: %v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.peers[config.RemoteAddress.String()]
	if exists {
		return ErrPeerAlreadyExists
	}
	p := newPeer(config, s.id, plugin, o)
	if s.serving {
		p.start()
	}
	s.peers[p.config.RemoteAddress.String()] = p
	return nil
}

// DeletePeer deletes a peer from the Server.
func (s *Server) DeletePeer(ip netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.peers[ip.String()]
	if !exists {
		return ErrPeerNotExist
	}
	if s.serving {
		p.stop()
	}
	delete(s.peers, ip.String())
	return nil
}

// GetPeer returns the configuration for the provided peer, or an error if it
// does not exist.
func (s *Server) GetPeer(ip netip.Addr) (PeerConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.peers[ip.String()]
	if !exists {
		return PeerConfig{}, ErrPeerNotExist
	}
	return p.config, nil
}

// ListPeers returns the configuration for all peers.
func (s *Server) ListPeers() []PeerConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	configs := make([]PeerConfig, 0)
	for _, peer := range s.peers {
		configs = append(configs, peer.config)
	}
	return configs
}
