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
	var codeDesc, subcodeDesc string
	d, ok := notifCodesMap[n.notification.Code]
	if ok {
		codeDesc = d.desc
		s, ok := d.subcodes[n.notification.Subcode]
		if ok {
			subcodeDesc = s
		}
	}
	return fmt.Sprintf("notification %s code: %d (%s) subcode: %d (%s)",
		direction, n.notification.Code, codeDesc, n.notification.Subcode,
		subcodeDesc)
}
