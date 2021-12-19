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
	peers map[netip.Addr]*peer

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

	return &Server{
		mu:            sync.Mutex{},
		id:            binary.BigEndian.Uint32(routerID.AsSlice()),
		peers:         make(map[netip.Addr]*peer),
		doneServingCh: make(chan struct{}),
		closeCh:       make(chan struct{}),
	}, nil
}

var (
	ErrServerClosed = errors.New("server closed")
	ErrPeerExist    = errors.New("peer already exists")
	ErrPeerNotExist = errors.New("peer does not exist")
)

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

				addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
				if err != nil {
					conn.Close()
					continue
				}

				s.mu.Lock()
				p, exists := s.peers[addrPort.Addr()]
				if !exists {
					conn.Close()
					s.mu.Unlock()
					continue
				}
				p.incomingConnection(conn)
				s.mu.Unlock()
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
	LocalAddress  netip.Addr
	RemoteAddress netip.Addr
	LocalAS       uint32
	RemoteAS      uint32
}

func (p PeerConfig) validate() error {
	if !p.LocalAddress.IsValid() {
		return errors.New("invalid local address")
	}

	if !p.RemoteAddress.IsValid() {
		return errors.New("invalid remote address")
	}

	if p.LocalAddress.Is4() != p.RemoteAddress.Is4() {
		return errors.New("invalid local/remote address pair")
	}

	// https://tools.ietf.org/html/rfc7607
	if p.LocalAS == 0 || p.RemoteAS == 0 {
		return errors.New("AS must be > 0")
	}

	return nil
}

// AddPeer adds a peer to the Server to be handled with the provided Plugin and PeerOptions.
func (s *Server) AddPeer(config PeerConfig, plugin Plugin, opts ...PeerOption) error {
	if err := config.validate(); err != nil {
		return fmt.Errorf("peer config invalid: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.peers[config.RemoteAddress]
	if exists {
		return ErrPeerExist
	}

	o := defaultPeerOptions()
	for _, opt := range opts {
		opt.apply(&o)
	}

	if err := o.validate(); err != nil {
		return fmt.Errorf("invalid peer options: %v", err)
	}

	p := newPeer(config, s.id, plugin, o)
	if s.serving {
		p.start()
	}

	s.peers[p.config.RemoteAddress] = p

	return nil
}

// DeletePeer deletes a peer from the Server.
func (s *Server) DeletePeer(ip netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.peers[ip]
	if !exists {
		return ErrPeerNotExist
	}

	p.stop()
	delete(s.peers, ip)

	return nil
}

// GetPeer returns the configuration for the provided peer, or an error if it does not exist.
func (s *Server) GetPeer(ip netip.Addr) (PeerConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, exists := s.peers[ip]
	if !exists {
		return PeerConfig{}, ErrPeerNotExist
	}

	return p.config, nil
}

// ListPeers returns the configuration for all peers.
func (s *Server) ListPeers() []PeerConfig {
	s.mu.Lock()
	defer s.mu.Unlock()

	configs := make([]PeerConfig, 0, len(s.peers))
	for _, peer := range s.peers {
		configs = append(configs, peer.config)
	}

	return configs
}
