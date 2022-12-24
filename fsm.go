package corebgp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type fsm struct {
	peer *peer

	// the bgp ID received in the latest open message
	remoteID uint32

	// conn-related fields
	conn         net.Conn
	dialResultCh chan *dialResult
	cancelDialFn context.CancelFunc

	// reader channels
	readerMsgCh     chan message
	readerErrCh     chan error
	readerDoneCh    chan struct{}
	closeReaderCh   chan struct{}
	closeReaderOnce sync.Once

	// control channels
	closeOnce sync.Once
	closeCh   chan struct{}
	doneCh    chan struct{}

	// timers
	connectRetryTimer *time.Timer
	holdTimer         *time.Timer
	holdTime          time.Duration
	keepAliveTimer    *time.Timer
	keepAliveInterval time.Duration
	idleHoldTimer     *time.Timer
}

func newFSM(peer *peer, conn net.Conn) *fsm {
	f := &fsm{
		peer:    peer,
		conn:    conn,
		closeCh: make(chan struct{}),
		doneCh:  make(chan struct{}),
		// we do not hold down the first time entering idle state
		idleHoldTimer: time.NewTimer(0),
	}
	return f
}

type fsmState uint8

func (f fsmState) String() string {
	switch f {
	case disabledState:
		return "disabled"
	case idleState:
		return "idle"
	case connectState:
		return "connect"
	case activeState:
		return "active"
	case openSentState:
		return "openSent"
	case openConfirmState:
		return "openConfirm"
	case establishedState:
		return "established"
	default:
		return "unknown"
	}
}

const (
	disabledState fsmState = iota
	idleState
	connectState
	activeState
	openSentState
	openConfirmState
	establishedState
)

func (f *fsm) cleanup() {
	if f.cancelDialFn != nil {
		f.cancelDialFn()
		<-f.dialResultCh
	}
	f.cleanupConnAndReader()
	for _, t := range []*time.Timer{f.connectRetryTimer, f.holdTimer,
		f.keepAliveTimer, f.idleHoldTimer} {
		if t != nil {
			t.Stop()
		}
	}
}

func (f *fsm) run() {
	defer func() {
		f.cleanup()
		close(f.doneCh)
	}()

	var t stateTransition
	if f.conn != nil {
		// if we start up with a non-nil conn we should enter into the active
		// state in order to skip connect and send an open message to the remote
		// peer.
		t = newStateTransition(disabledState, activeState)
	} else {
		t = newStateTransition(disabledState, idleState)
	}

	for {
		// capture target state before peer coordination
		toBefore := t.to

		// signal state transition to local peer manager for coordination with
		// the "other" fsm.
		select {
		case f.peer.getFSMTransitionCh(f) <- t:
			select {
			case <-f.closeCh:
				t = newStateTransition(t.from, disabledState)
			case t = <-f.peer.getFSMTransitionCh(f):
			}
		case <-f.closeCh:
			t = newStateTransition(t.from, disabledState)
		}

		if t.to != toBefore && t.to == disabledState && f.conn != nil &&
			t.from > activeState {
			// we were disabled while transitioning to a target state with an
			// active connection
			f.sendNotification(newNotification(NOTIF_CODE_CEASE, 0, nil)) // nolint: errcheck
		}

		var (
			desired fsmState
			err     error
		)
		switch t.to {
		case disabledState:
			return
		case idleState:
			desired = f.idle()
		case connectState:
			desired = f.connect()
		case activeState:
			desired = f.active()
		case openSentState:
			desired, err = f.openSent()
		case openConfirmState:
			desired, err = f.openConfirm()
		case establishedState:
			desired, err = f.established()
		}

		if err != nil {
			// if an error occurred we signal it to the peer
			select {
			case <-f.closeCh:
				t = newStateTransition(t.to, disabledState)
			case f.peer.getFSMErrorCh(f) <- err:
				t = newStateTransition(t.to, desired)
			}
		} else {
			t = newStateTransition(t.to, desired)
		}
	}
}

func (f *fsm) start() {
	go f.run()
}

func (f *fsm) stop() {
	f.closeOnce.Do(func() {
		close(f.closeCh)
	})
	<-f.doneCh
}

type stateTransition struct {
	from fsmState
	to   fsmState
}

func newStateTransition(from fsmState, to fsmState) stateTransition {
	return stateTransition{
		from: from,
		to:   to,
	}
}

type dialResult struct {
	conn net.Conn
	err  error
}

func (f *fsm) dialPeer() {
	ctx, cancel := context.WithCancel(context.Background())
	dialResultCh := make(chan *dialResult)
	f.dialResultCh = dialResultCh
	f.cancelDialFn = cancel
	go func() {
		defer close(f.dialResultCh)
		var (
			laddr net.Addr
			err   error
		)
		if f.peer.options.localAddress.IsValid() {
			laddr, err = net.ResolveTCPAddr("tcp",
				net.JoinHostPort(f.peer.options.localAddress.String(), "0"))
			if err != nil {
				dialResultCh <- &dialResult{
					conn: nil,
					err:  err,
				}
			}
		}
		dialer := &net.Dialer{
			LocalAddr: laddr,
			Control:   f.peer.options.dialerControlFn,
		}
		conn, err := dialer.DialContext(ctx, "tcp",
			net.JoinHostPort(f.peer.config.RemoteAddress.String(),
				strconv.Itoa(f.peer.options.port)))
		dialResultCh <- &dialResult{
			conn: conn,
			err:  err,
		}
	}()
}

// https://tools.ietf.org/html/rfc4271#section-8.2.2
func (f *fsm) idle() fsmState {
	/*
		In this state, BGP FSM refuses all incoming BGP connections for
		this peer.  No resources are allocated to the peer.  In response
		to a ManualStart event (Event 1) or an AutomaticStart event (Event
		3), the local system:

			- initializes all BGP resources for the peer connection,
			- sets ConnectRetryCounter to zero,
			- starts the ConnectRetryTimer with the initial value,
			- initiates a TCP connection to the other BGP peer,
			- listens for a connection that may be initiated by the remote
			BGP peer, and
			- changes its state to Connect.

		The ManualStop event (Event 2) and AutomaticStop (Event 8) event
		are ignored in the Idle state.
	*/
	select {
	case <-f.closeCh:
		return disabledState
	case <-f.idleHoldTimer.C:
		f.connectRetryTimer = time.NewTimer(f.peer.options.connectRetryTime)
		f.dialPeer()
		f.idleHoldTimer.Reset(f.peer.options.idleHoldTime)
		return connectState
	}
}

const (
	// a long hold time is set when transitioning to openSent.
	// RFC4271 suggests 4 minutes.
	longHoldTime = time.Minute * 4
)

func (f *fsm) sendOpenAndSetHoldTimer() fsmState {
	capabilities := f.peer.plugin.GetCapabilities(f.peer.config)
	o, err := newOpenMessage(f.peer.config.LocalAS, f.peer.options.holdTime,
		f.peer.id, capabilities)
	if err != nil {
		f.conn.Close()
		return idleState
	}
	b, err := o.encode()
	if err != nil {
		f.conn.Close()
		return idleState
	}
	_, err = f.conn.Write(b)
	if err != nil {
		f.conn.Close()
		return idleState
	}
	f.holdTimer = time.NewTimer(longHoldTime)
	f.startReading()
	return openSentState
}

// https://tools.ietf.org/html/rfc4271#page-54
func (f *fsm) connect() fsmState {
	for {
		select {
		case <-f.closeCh:
			f.cancelDialFn()
			<-f.dialResultCh
			f.connectRetryTimer.Stop()
			return disabledState
		case dr := <-f.dialResultCh:
			if dr.err != nil {
				/*
					https://tools.ietf.org/html/rfc4271#page-56
					If the TCP connection fails (Event 18), the local system checks
					the DelayOpenTimer.  If the DelayOpenTimer is running, the local
					system: [...]

					If the DelayOpenTimer is not running, the local system:

						- stops the ConnectRetryTimer to zero,
						- drops the TCP connection,
						- releases all BGP resources, and
						- changes its state to Idle.
				*/
				f.connectRetryTimer.Stop()
				f.cancelDialFn()
				return idleState
			}

			/*
				https://tools.ietf.org/html/rfc4271#page-55
				If the TCP connection succeeds (Event 16 or Event 17), the local
				system checks the DelayOpen attribute prior to processing.  If the
				DelayOpen attribute is set to TRUE, the local system: [...]

				If the DelayOpen attribute is set to FALSE, the local system:

					- stops the ConnectRetryTimer (if running) and sets the
					  ConnectRetryTimer to zero,
					- completes BGP initialization
					- sends an OPEN message to its peer,
					- sets the HoldTimer to a large value, and
					- changes its state to OpenSent.

				A HoldTimer value of 4 minutes is suggested.
			*/
			f.conn = dr.conn
			f.connectRetryTimer.Stop()
			return f.sendOpenAndSetHoldTimer()
		case <-f.connectRetryTimer.C:
			/*
				https://tools.ietf.org/html/rfc4271#page-55
				In response to the ConnectRetryTimer_Expires event (Event 9), the
				local system:

					- drops the TCP connection,
					- restarts the ConnectRetryTimer,
					- stops the DelayOpenTimer and resets the timer to zero,
					- initiates a TCP connection to the other BGP peer,
					- continues to listen for a connection that may be initiated by
					the remote BGP peer, and
					- stays in the Connect state.
			*/
			f.cancelDialFn()
			dr := <-f.dialResultCh
			if dr.err != nil {
				f.connectRetryTimer = time.NewTimer(f.peer.options.connectRetryTime)
				f.dialPeer()
				continue
			}
			// if dr.err == nil we ended up with an established connection
			// during the race between connectRetryTimer and the dialer
			f.conn = dr.conn
			return f.sendOpenAndSetHoldTimer()
		}
	}
}

// https://tools.ietf.org/html/rfc4271#page-59
func (f *fsm) active() fsmState {
	// if conn is non-nil we were started up with a valid connection as part
	// of handling an incoming connection. If conn is nil we are an "outgoing"
	// connection FSM
	if f.conn != nil {
		return f.sendOpenAndSetHoldTimer()
	}

	/*
		https://tools.ietf.org/html/rfc4271#page-59
		In response to a ConnectRetryTimer_Expires event (Event 9), the
		local system:

			- restarts the ConnectRetryTimer (with initial value),
			- initiates a TCP connection to the other BGP peer,
			- continues to listen for a TCP connection that may be initiated
			  by a remote BGP peer, and
			- changes its state to Connect.
	*/
	select {
	case <-f.connectRetryTimer.C:
		f.connectRetryTimer = time.NewTimer(f.peer.options.connectRetryTime)
		f.dialPeer()
		return connectState
	case <-f.closeCh:
		return disabledState
	}
}

const (
	maxMessageLength = 4096
)

func (f *fsm) startReading() {
	f.closeReaderCh = make(chan struct{})
	f.closeReaderOnce = sync.Once{}
	f.readerDoneCh = make(chan struct{})
	f.readerErrCh = make(chan error)
	f.readerMsgCh = make(chan message)
	go f.read()
}

func (f *fsm) cleanupConnAndReader() {
	defer func() {
		f.conn = nil
	}()
	if f.conn != nil {
		f.conn.Close()
	}
	if f.closeReaderCh == nil {
		return
	}
	f.closeReaderOnce.Do(func() {
		close(f.closeReaderCh)
	})
	<-f.readerDoneCh
}

func (f *fsm) read() {
	defer close(f.readerDoneCh)

	for {
		header := make([]byte, headerLength)
		_, err := io.ReadFull(f.conn, header)
		if err != nil {
			select {
			case <-f.closeReaderCh:
				return
			case f.readerErrCh <- err:
				return
			}
		}

		for i := 0; i < 16; i++ {
			if header[i] != 0xFF {
				n := newNotification(NOTIF_CODE_MESSAGE_HEADER_ERR,
					NOTIF_SUBCODE_CONN_NOT_SYNCHRONIZED, nil)
				select {
				case <-f.closeReaderCh:
					return
				case f.readerErrCh <- newNotificationError(n, true):
					return
				}
			}
		}

		// length is inclusive of header
		bodyLen := int(binary.BigEndian.Uint16(header[16:18])) - headerLength
		if bodyLen < 0 || bodyLen+headerLength > maxMessageLength {
			n := newNotification(NOTIF_CODE_MESSAGE_HEADER_ERR,
				NOTIF_SUBCODE_BAD_MESSAGE_LEN, nil)
			select {
			case <-f.closeReaderCh:
				return
			case f.readerErrCh <- newNotificationError(n, true):
				return
			}
		}

		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			_, err = io.ReadFull(f.conn, body)
			if err != nil {
				select {
				case <-f.closeReaderCh:
					return
				case f.readerErrCh <- err:
					return
				}
			}
		}

		m, err := messageFromBytes(body, header[18])
		if err != nil {
			select {
			case <-f.closeReaderCh:
				return
			case f.readerErrCh <- err:
				return
			}
		}
		select {
		case <-f.closeReaderCh:
			return
		case f.readerMsgCh <- m:
		}
	}
}

func (f *fsm) sendNotification(n *Notification) error {
	b, err := n.encode()
	if err != nil {
		return err
	}
	_, err = f.conn.Write(b)
	return err
}

func (f *fsm) sendKeepAlive() error {
	k := keepAliveMessage{}
	b, err := k.encode()
	if err != nil {
		return err
	}
	_, err = f.conn.Write(b)
	return err
}

func (f *fsm) drainAndResetHoldTimer() {
	if !f.holdTimer.Stop() {
		<-f.holdTimer.C
	}
	f.holdTimer.Reset(f.holdTime)
}

// handleNotificationInErr checks if the error unwraps to a notificationError.
// If a notificationError is found and its out field is true, the Notification
// is sent to the peer and the function returns true, otherwise it returns
// false.
func (f *fsm) handleNotificationInErr(err error) bool {
	var nerr *notificationError
	if errors.As(err, &nerr) && nerr.out {
		f.sendNotification(nerr.notification) // nolint: errcheck
		return true
	}
	return false
}

// https://tools.ietf.org/html/rfc4271#page-63
func (f *fsm) openSent() (fsmState, error) {
	openSent := func() (fsmState, error) {
		select {
		case <-f.closeCh:
			n := newNotification(NOTIF_CODE_CEASE, 0, nil)
			f.sendNotification(n) // nolint: errcheck
			return disabledState, newNotificationError(n, true)
		case <-f.holdTimer.C:
			/*
				https://tools.ietf.org/html/rfc4271#page-64
				If the HoldTimer_Expires (Event 10), the local system:

					 - sends a NOTIFICATION message with the error code Hold Timer
					   Expired,
					 - sets the ConnectRetryTimer to zero,
					 - releases all BGP resources,
					 - drops the TCP connection,
					 - increments the ConnectRetryCounter,
					 - (optionally) performs peer oscillation damping if the
					   DampPeerOscillations attribute is set to TRUE, and
					 - changes its state to Idle.
			*/
			n := newNotification(NOTIF_CODE_HOLD_TIMER_EXPIRED, 0, nil)
			f.sendNotification(n) // nolint: errcheck
			return idleState, newNotificationError(n, true)
		case err := <-f.readerErrCh:
			f.handleNotificationInErr(err)

			var nerr *notificationError
			if errors.As(err, &nerr) {
				return idleState, fmt.Errorf("reader error: %w", nerr)
			}
			// if it's not a notificationError, it's connection-related

			/*
				https://tools.ietf.org/html/rfc4271#page-64
				If a TcpConnectionFails event (Event 18) is received, the local
				system:

				   - closes the BGP connection,
				   - restarts the ConnectRetryTimer,
				   - continues to listen for a connection that may be initiated by
					 the remote BGP peer, and
				   - changes its state to Active.

			*/
			f.connectRetryTimer = time.NewTimer(f.peer.options.connectRetryTime)
			return activeState, fmt.Errorf("reader error: %w", err)
		case m := <-f.readerMsgCh:
			switch m := m.(type) {
			case *Notification:
				return idleState, newNotificationError(m, false)
			case *openMessage:
				/*
					https://tools.ietf.org/html/rfc4271#page-65
					When an OPEN message is received, all fields are checked for
					correctness.  If there are no errors in the OPEN message (Event
					19), the local system:

						- resets the DelayOpenTimer to zero,
						- sets the BGP ConnectRetryTimer to zero,
						- sends a KEEPALIVE message, and
						- sets a KeepaliveTimer (via the text below)
						- sets the HoldTimer according to the negotiated value (see
						  Section 4.2),
						- changes its state to OpenConfirm.
				*/
				err := m.validate(f.peer.id, f.peer.config.LocalAS,
					f.peer.config.RemoteAS)
				if err != nil {
					f.handleNotificationInErr(err)
					return idleState, fmt.Errorf("error validating open message: %w", err)
				}
				f.remoteID = m.bgpID
				var ridA [4]byte
				binary.BigEndian.PutUint32(ridA[:], m.bgpID)
				rid := netip.AddrFrom4(ridA)
				n := f.peer.plugin.OnOpenMessage(f.peer.config, rid, m.getCapabilities())
				if n != nil {
					f.sendNotification(n) // nolint: errcheck
					return idleState, newNotificationError(n, true)
				}

				err = f.sendKeepAlive()
				if err != nil {
					return idleState, fmt.Errorf("error sending keepAlive: %w", err)
				}

				f.holdTime = time.Duration(m.holdTime) * time.Second
				if f.peer.options.holdTime < f.holdTime {
					f.holdTime = f.peer.options.holdTime
				}
				if f.holdTime != 0 {
					// https://tools.ietf.org/html/rfc4271#section-4.4
					// A reasonable maximum time between KEEPALIVE messages would be one
					// third of the Hold Time interval.
					f.keepAliveInterval = f.holdTime / 3
					f.keepAliveTimer = time.NewTimer(f.keepAliveInterval)
					f.drainAndResetHoldTimer()
				}

				return openConfirmState, nil
			default:
				/*
					https://tools.ietf.org/html/rfc4271#page-66
					In response to any other event (Events 9, 11-13, 20, 25-28), the
					local system:

						- sends the NOTIFICATION with the Error Code Finite State
						  Machine Error,
						- sets the ConnectRetryTimer to zero,
						- releases all BGP resources,
						- drops the TCP connection,
						- increments the ConnectRetryCounter by 1,
						- (optionally) performs peer oscillation damping if the
						  DampPeerOscillations attribute is set to TRUE, and
						- changes its state to Idle.

					https://tools.ietf.org/html/rfc6608#section-4
					If a BGP speaker receives an unexpected message (e.g., KEEPALIVE/
					UPDATE/ROUTE-REFRESH message) on a session in OpenSent state, it MUST
					send to the neighbor a NOTIFICATION message with the Error Code
					Finite State Machine Error and the Error Subcode "Receive Unexpected
					Message in OpenSent State".  The Data field is a 1-octet, unsigned
					integer that indicates the type of the unexpected message.
				*/
				n := newNotification(NOTIF_CODE_FSM_ERR,
					NOTIF_SUBCODE_RX_UNEXPECTED_MESSAGE_OPENSENT,
					[]byte{m.messageType()})
				f.sendNotification(n) // nolint: errcheck
				return idleState, newNotificationError(n, true)
			}
		}
	}

	to, err := openSent()
	if to != openConfirmState {
		f.cleanupConnAndReader()
		f.holdTimer.Stop()
	}
	return to, err
}

// https://tools.ietf.org/html/rfc4271#page-67
func (f *fsm) openConfirm() (fsmState, error) {
	openConfirm := func() (fsmState, error) {
		for {
			select {
			case <-f.closeCh:
				n := newNotification(NOTIF_CODE_CEASE, 0, nil)
				f.sendNotification(n) // nolint: errcheck
				return disabledState, newNotificationError(n, true)
			case <-f.holdTimer.C:
				n := newNotification(NOTIF_CODE_HOLD_TIMER_EXPIRED, 0, nil)
				f.sendNotification(n) // nolint: errcheck
				return idleState, newNotificationError(n, true)
			case <-f.keepAliveTimer.C:
				err := f.sendKeepAlive()
				if err != nil {
					return idleState, fmt.Errorf("error sending keepAlive: %w", err)
				}
				f.keepAliveTimer.Reset(f.keepAliveInterval)
				continue
			case err := <-f.readerErrCh:
				// In OpenConfirm handling of a TCP connection fails event or
				// message decoding error both result in transitioning to Idle.
				f.handleNotificationInErr(err)
				return idleState, fmt.Errorf("reader error: %w", err)
			case m := <-f.readerMsgCh:
				switch m := m.(type) {
				case *keepAliveMessage:
					/*
						https://tools.ietf.org/html/rfc4271#page-70
						If the local system receives a KEEPALIVE message (KeepAliveMsg
						(Event 26)), the local system:

							- restarts the HoldTimer and
							- changes its state to Established.
					*/
					f.drainAndResetHoldTimer()
					return establishedState, nil
				case *Notification:
					return idleState, newNotificationError(m, false)
				default:
					/*
						https://tools.ietf.org/html/rfc4271#page-70
						In response to any other event (Events 9, 12-13, 20, 27-28), the
						local system:

							- sends a NOTIFICATION with a code of Finite State Machine
							  Error,
							- sets the ConnectRetryTimer to zero,
							- releases all BGP resources,
							- drops the TCP connection,
							- increments the ConnectRetryCounter by 1,
							- (optionally) performs peer oscillation damping if the
							  DampPeerOscillations attribute is set to TRUE, and
							- changes its state to Idle.

						https://tools.ietf.org/html/rfc6608#page-3
						If a BGP speaker receives an unexpected message (e.g., OPEN/UPDATE/
						ROUTE-REFRESH message) on a session in OpenConfirm state, it MUST
						send a NOTIFICATION message with the Error Code Finite State Machine
						Error and the Error Subcode "Receive Unexpected Message in
						OpenConfirm State" to the neighbor.  The Data field is a 1-octet,
						unsigned integer that indicates the type of the unexpected message.
					*/
					n := newNotification(NOTIF_CODE_FSM_ERR,
						NOTIF_SUBCODE_RX_UNEXPECTED_MESSAGE_OPENCONFIRM,
						[]byte{m.messageType()})
					f.sendNotification(n) // nolint: errcheck
					return idleState, newNotificationError(n, true)
				}
			}
		}
	}

	to, err := openConfirm()
	if to != establishedState {
		f.cleanupConnAndReader()
		f.holdTimer.Stop()
		f.keepAliveTimer.Stop()
	}
	return to, err
}

type updateMessageWriter struct {
	conn           net.Conn
	resetKATimerCh chan struct{}
	closeCh        chan struct{}
}

func (u *updateMessageWriter) WriteUpdate(b []byte) error {
	/*
		https://tools.ietf.org/html/rfc4271#page-72
		Each time the local system sends a KEEPALIVE or UPDATE message, it
		restarts its KeepaliveTimer, unless the negotiated HoldTime value
		is zero.
	*/
	select {
	case <-u.closeCh:
		return io.ErrClosedPipe
	default:
		_, err := u.conn.Write(prependHeader(b, updateMessageType))
		if err == nil {
			select {
			case <-u.closeCh:
			case u.resetKATimerCh <- struct{}{}:
			}
		}
		return err
	}
}

// https://tools.ietf.org/html/rfc4271#page-71
func (f *fsm) established() (fsmState, error) {
	// A separate goroutine is used for resetting the keepAlive timer to
	// allow both our main select{} in the established() func below and the
	// updateMessageWriter to reset it without synchronizing all input and
	// output in the same select{}. Synchronizing all I/O in the same select{}
	// would have a negative impact on performance.
	kaManagerDoneCh := make(chan struct{})
	closeKAManagerCh := make(chan struct{})
	resetKATimerCh := make(chan struct{})
	go func() {
		defer close(kaManagerDoneCh)
		for {
			select {
			case <-closeKAManagerCh:
				return
			case <-resetKATimerCh:
				if f.holdTime != 0 {
					f.keepAliveTimer.Reset(f.keepAliveInterval)
				}
			}
		}
	}()

	established := func() (fsmState, error) {
		writer := &updateMessageWriter{
			conn:           f.conn,
			resetKATimerCh: resetKATimerCh,
			closeCh:        make(chan struct{}),
		}
		defer func() {
			close(closeKAManagerCh)
			close(writer.closeCh)
		}()
		handler := f.peer.plugin.OnEstablished(f.peer.config, writer)

		for {
			select {
			case <-f.closeCh:
				n := newNotification(NOTIF_CODE_CEASE, 0, nil)
				f.sendNotification(n) // nolint: errcheck
				return disabledState, newNotificationError(n, true)
			case <-f.holdTimer.C:
				n := newNotification(NOTIF_CODE_HOLD_TIMER_EXPIRED, 0, nil)
				f.sendNotification(n) // nolint: errcheck
				return idleState, newNotificationError(n, true)
			case <-f.keepAliveTimer.C:
				err := f.sendKeepAlive()
				if err != nil {
					return idleState, fmt.Errorf("error sending keepAlive: %w", err)
				}
				resetKATimerCh <- struct{}{}
			case err := <-f.readerErrCh:
				f.handleNotificationInErr(err)
				return idleState, fmt.Errorf("error from reader: %w", err)
			case m := <-f.readerMsgCh:
				switch m := m.(type) {
				case *Notification:
					/*
						https://tools.ietf.org/html/rfc4271#page-73
						If the local system receives a NOTIFICATION message (Event 24 or
						Event 25) or a TcpConnectionFails (Event 18) from the underlying
						TCP, the local system:

							- sets the ConnectRetryTimer to zero,
							- deletes all routes associated with this connection,
							- releases all the BGP resources,
							- drops the TCP connection,
							- increments the ConnectRetryCounter by 1,
							- changes its state to Idle.
					*/
					return idleState, newNotificationError(m, false)
				case *keepAliveMessage:
					/*
						https://tools.ietf.org/html/rfc4271#page-74
						If the local system receives a KEEPALIVE message (Event 26), the
						local system:

							- restarts its HoldTimer, if the negotiated HoldTime value is
							  non-zero, and
							- remains in the Established state.
					*/
					if f.holdTime != 0 {
						f.drainAndResetHoldTimer()
					}
					continue
				case updateMessage:
					/*
						If the local system receives an UPDATE message (Event 27), the
						local system:

							- processes the message,
							- restarts its HoldTimer, if the negotiated HoldTime value is
							  non-zero, and
							- remains in the Established state.
					*/
					if handler != nil {
						n := handler(f.peer.config, m)
						if n != nil {
							f.sendNotification(n) // nolint: errcheck
							return idleState, newNotificationError(n, true)
						}
					}
					if f.holdTime != 0 {
						f.drainAndResetHoldTimer()
					}
					continue
				default:
					/*
						https://tools.ietf.org/html/rfc4271#page-74
						In response to any other event (Events 9, 12-13, 20-22), the local
						system:

							- sends a NOTIFICATION message with the Error Code Finite State
							  Machine Error,
							- deletes all routes associated with this connection,
							- sets the ConnectRetryTimer to zero,
							- releases all BGP resources,
							- drops the TCP connection,
							- increments the ConnectRetryCounter by 1,
							- (optionally) performs peer oscillation damping if the
							  DampPeerOscillations attribute is set to TRUE, and
							- changes its state to Idle.

						https://tools.ietf.org/html/rfc6608#page-3
						If a BGP speaker receives an unexpected message (e.g., OPEN message)
						on a session in Established State, it MUST send to the neighbor a
						NOTIFICATION message with the Error Code Finite State Machine Error
						and the Error Subcode "Receive Unexpected Message in Established
						State".  The Data field is a 1-octet, unsigned integer that indicates
						the type of the unexpected message.
					*/
					n := newNotification(NOTIF_CODE_FSM_ERR,
						NOTIF_SUBCODE_RX_UNEXPECTED_MESSAGE_ESTABLISHED,
						[]byte{m.messageType()})
					f.sendNotification(n) // nolint: errcheck
					return idleState, newNotificationError(n, true)
				}
			}
		}
	}

	to, err := established()
	f.cleanupConnAndReader()
	f.holdTimer.Stop()
	f.keepAliveTimer.Stop()
	f.peer.plugin.OnClose(f.peer.config)
	return to, err
}
