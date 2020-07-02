package corebgp

import (
	"errors"
	"net"
	"sync"
	"time"
)

const (
	// the amount of time after which we forget about a previously encountered
	// protocol error leading to a reset of startupDelay
	errorAmnesiaTime = time.Second * 300
	// the minimum amount of startup delay incurred from a protocol error
	errorDelayMinTime = time.Second * 60
	// the maximum amount of startup delay incurred from a protocol error
	errorDelayMaxTime = time.Second * 300
)

// peer manages the FSMs for a peer.
type peer struct {
	config  *PeerConfig
	id      uint32
	plugin  Plugin
	options *peerOptions

	fsms         [2]*fsm
	fsmState     [2]fsmState
	transitionCh [2]chan stateTransition
	errorCh      [2]chan error

	lastProtoError    *time.Time
	startupDelay      time.Duration
	startupDelayTimer *time.Timer
	inHoldDown        bool

	inConnCh  chan net.Conn
	closeOnce sync.Once
	closeCh   chan struct{}
	doneCh    chan struct{}
}

const (
	out = 0
	in  = 1
)

func newPeer(config *PeerConfig, id uint32, plugin Plugin, options *peerOptions) *peer {
	p := &peer{
		config:            config,
		id:                id,
		plugin:            plugin,
		options:           options,
		inConnCh:          make(chan net.Conn),
		closeCh:           make(chan struct{}),
		doneCh:            make(chan struct{}),
		startupDelayTimer: time.NewTimer(0),
	}
	<-p.startupDelayTimer.C
	for i := 0; i < 2; i++ {
		p.fsmState[i] = disabledState
		p.transitionCh[i] = make(chan stateTransition)
		p.errorCh[i] = make(chan error)
	}
	return p
}

// getFSMTransitionCh returns the stateTransition channel for the provided FSM.
func (p *peer) getFSMTransitionCh(f *fsm) chan stateTransition {
	if f == p.fsms[out] {
		return p.transitionCh[out]
	}
	return p.transitionCh[in]
}

// getFSMErrorCh returns the error channel for the provided FSM.
func (p *peer) getFSMErrorCh(f *fsm) chan error {
	if f == p.fsms[out] {
		return p.errorCh[out]
	}
	return p.errorCh[in]
}

func other(i int) int {
	if i == out {
		return in
	}
	return out
}

func (p *peer) logTransition(i int, from, to fsmState) {
	logf("[%s] FSM-%s transition %s => %s", p.config.IP,
		direction(i), from, to)
}

func (p *peer) disableFSM(i int) {
	if p.fsms[i] == nil {
		return
	}
	p.logTransition(i, p.fsmState[i], disabledState)
	p.fsms[i].stop()
	p.fsms[i] = nil
	p.fsmState[i] = disabledState
}

func (p *peer) sendTransitionToFSM(i int, t stateTransition) {
	select {
	case <-p.closeCh:
		return
	case p.transitionCh[i] <- t:
		p.logTransition(i, t.from, t.to)
		p.fsmState[i] = t.to
	}
}

func (p *peer) enableFSM(i int, conn net.Conn) {
	if i == out && p.options.passive {
		return
	}
	if p.fsms[i] == nil {
		p.fsms[i] = newFSM(p, conn)
		p.fsmState[i] = disabledState
		p.fsms[i].start()
	}
}

func (p *peer) handleStateTransition(i int, t stateTransition) {
	switch {
	case t.to == establishedState:
		// disable the other fsm
		p.disableFSM(other(i))
		p.sendTransitionToFSM(i, t)
	case i == in && t.to < t.from:
		// in going down, disable it and make sure out is enabled
		p.disableFSM(i)
		p.enableFSM(out, nil)
	case t.to == openConfirmState:
		// https://tools.ietf.org/html/rfc4271#section-6.8
		switch p.fsmState[other(i)] {
		case establishedState:
			/*
				Unless allowed via configuration, a connection collision with an
				existing BGP connection that is in the Established state causes
				closing of the newly created connection.
			*/
			p.disableFSM(i)
		case openConfirmState:
			// https://github.com/BIRD/bird/blob/v2.0.2/proto/bgp/packets.c#L666
			/*
				Description of collision detection rules in RFC 4271 is confusing and
				contradictory, but it is essentially:

					1. Router with higher ID is dominant
					2. If both have the same ID, router with higher ASN is dominant [RFC6286]
					3. When both connections are in OpenConfirm state, one initiated by
					 the dominant router is kept.
			*/
			remoteID := p.fsms[i].remoteID
			localID := p.id
			dominant := localID > remoteID ||
				(localID == remoteID) && (p.config.LocalAS > p.config.RemoteAS)
			if dominant && i == out {
				// attempt to disable other FSM
				select {
				case <-p.closeCh:
					return
				case p.fsms[other(i)].closeCh <- struct{}{}:
					// we send an empty struct rather than close the channel in
					// case we lose on the select race in fsm.openConfirm()
					p.disableFSM(other(i)) // wait for it to stop completely
					p.sendTransitionToFSM(i, t)
				case otherT := <-p.transitionCh[other(i)]:
					// other FSM transitioned before we could disable it
					if otherT.to == establishedState {
						// other FSM entered established state before we could
						// disable it. disable this FSM and then handle the
						// transition from the other FSM.
						p.disableFSM(i)
						p.handleStateTransition(other(i), otherT)
					} else {
						// other FSM went down, allow this FSM to transition to
						// openConfirm and then handle the transition from the
						// other FSM.
						p.sendTransitionToFSM(i, t)
						p.handleStateTransition(other(i), otherT)
					}
				}
			} else {
				// disable this fsm
				p.disableFSM(i)
			}
		default:
			p.sendTransitionToFSM(i, t)
		}
	default:
		p.sendTransitionToFSM(i, t)
	}
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func direction(i int) string {
	if i == in {
		return "in"
	}
	return "out"
}

// handleError handles an error during fsm operation
func (p *peer) handleError(i int, err error) {
	logf("[%s] FSM-%s %s error: %v",
		p.config.IP, direction(i), p.fsmState[i], err)
	var nerr *notificationError
	if errors.As(err, &nerr) {
		if nerr.dampPeer() {
			p.disableFSM(in)
			p.disableFSM(out)
			p.updateStartupDelay()
			p.inHoldDown = true
		}
	}
}

// updateStartupDelay manages startupDelay and startupDelayTimer when an error
// requiring damping occurs in one of the FSMs. This logic is strongly
// influenced by bird's implementation found here
// https://github.com/BIRD/bird/blob/v2.0.2/proto/bgp/bgp.c#L384
func (p *peer) updateStartupDelay() {
	if p.lastProtoError != nil &&
		(time.Now().Sub(*p.lastProtoError) >= errorAmnesiaTime) {
		p.startupDelay = 0
	}

	lastProtoError := time.Now()
	p.lastProtoError = &lastProtoError

	if p.startupDelay > 0 {
		p.startupDelay = min(2*p.startupDelay, errorDelayMaxTime)
	} else {
		p.startupDelay = errorDelayMinTime
	}

	p.startupDelayTimer.Stop()
	p.startupDelayTimer = time.NewTimer(p.startupDelay)
	logf("[%s] damping peer for %s", p.config.IP, p.startupDelay)
}

// main run loop
func (p *peer) run() {
	defer func() {
		p.disableFSM(out)
		p.disableFSM(in)
		p.startupDelayTimer.Stop()
		close(p.doneCh)
	}()

	for {
		select {
		case <-p.closeCh:
			return
		case <-p.startupDelayTimer.C:
			logf("[%s] startup delay timer expired, enabling peer",
				p.config.IP)
			p.enableFSM(out, nil)
			p.inHoldDown = false
		case err := <-p.errorCh[in]:
			p.handleError(in, err)
		case err := <-p.errorCh[out]:
			p.handleError(out, err)
		case t := <-p.transitionCh[in]:
			p.handleStateTransition(in, t)
		case t := <-p.transitionCh[out]:
			p.handleStateTransition(out, t)
		case conn := <-p.inConnCh:
			if p.inHoldDown {
				conn.Close()
				continue
			}

			// https://github.com/BIRD/bird/blob/v2.0.2/proto/bgp/bgp.c#L1036
			if p.fsms[in] != nil || p.fsmState[out] == establishedState {
				conn.Close()
				continue
			} else {
				p.enableFSM(in, conn)
			}
		}
	}
}

func (p *peer) start() {
	p.enableFSM(out, nil)
	go p.run()
}

func (p *peer) stop() {
	p.closeOnce.Do(func() {
		close(p.closeCh)
	})
	<-p.doneCh
}

func (p *peer) incomingConnection(conn net.Conn) {
	select {
	case <-p.closeCh:
		conn.Close()
		return
	case p.inConnCh <- conn:
	}
}
