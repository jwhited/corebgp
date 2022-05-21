package corebgp

import "fmt"

type notificationError struct {
	notification *Notification
	out          bool
}

func newNotificationError(n *Notification, out bool) *notificationError {
	return &notificationError{
		notification: n,
		out:          out,
	}
}

func (n *notificationError) dampPeer() bool {
	return n.notification.Code != NOTIF_CODE_CEASE
}

func (n *notificationError) Error() string {
	direction := "received"
	if n.out {
		direction = "sent"
	}
	desc := lookupNotifDesc(n.notification.Code, n.notification.Subcode)
	return fmt.Sprintf("notification %s '%s' code: %d subcode: %d",
		direction, desc, n.notification.Code, n.notification.Subcode)
}

func lookupNotifDesc(code, subcode uint8) string {
	for _, desc := range notifDescs {
		if desc.code == code && desc.subcode == subcode {
			return desc.description
		}
	}
	return "Unknown description"
}

var (
	// most descriptions come from https://tools.ietf.org/html/rfc4271#section-4.5
	notifDescs = []struct {
		code        uint8
		subcode     uint8
		description string
	}{
		{1, 0, "Invalid message header"},
		{1, 1, "Connection not synchronized"},
		{1, 2, "Bad message length"},
		{1, 3, "Bad message type"},

		{2, 0, "Invalid OPEN message"},
		{2, 1, "Unsupported version number"},
		{2, 2, "Bad peer AS"},
		{2, 3, "Bad BGP identifier"},
		{2, 4, "Unsupported optional parameter"},
		{2, 6, "Unacceptable hold time"},
		// https://tools.ietf.org/html/rfc5492#section-5
		{2, 7, "Required capability missing"},

		{3, 0, "Invalid UPDATE message"},
		{3, 1, "Malformed attribute list"},
		{3, 2, "Unrecognized well-known attribute"},
		{3, 3, "Missing mandatory attribute"},
		{3, 4, "Invalid attribute flags"},
		{3, 5, "Invalid attribute length"},
		{3, 6, "Invalid ORIGIN attribute"},
		{3, 8, "Invalid NEXT_HOP attribute"},
		{3, 9, "Optional attribute error"},
		{3, 10, "Invalid network field"},
		{3, 11, "Malformed AS_PATH"},

		{4, 0, "Hold timer expired"},

		{5, 0, "Finite state machine error"},
		// https://tools.ietf.org/html/rfc6608#section-3
		{5, 1, "Unexpected message in OpenSent state"},
		{5, 2, "Unexpected message in OpenConfirm state"},
		{5, 3, "Unexpected message in Established state"},

		{6, 0, "Cease"},
		// https://tools.ietf.org/html/rfc4486#section-3
		{6, 1, "Maximum number of prefixes reached"},
		{6, 2, "Administrative shutdown"},
		{6, 3, "Peer de-configured"},
		{6, 4, "Administrative reset"},
		{6, 5, "Connection rejected"},
		{6, 6, "Other configuration change"},
		{6, 7, "Connection collision resolution"},
		{6, 8, "Out of Resources"},

		// https://tools.ietf.org/html/rfc7313#section-5
		{7, 0, "Invalid ROUTE-REFRESH message"},
		{7, 1, "Invalid ROUTE-REFRESH message length"},
	}
)
