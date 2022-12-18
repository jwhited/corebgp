package corebgp

import (
	"github.com/stretchr/testify/assert"
	"net/netip"
	"reflect"
	"testing"
)

func TestServer(t *testing.T) {
	_, err := NewServer(netip.Addr{})
	assert.Error(t, err)

	_, err = NewServer(netip.MustParseAddr("::1"))
	assert.Error(t, err)

	s, err := NewServer(netip.MustParseAddr("127.0.0.1"))
	assert.NoError(t, err)

	err = s.AddPeer(PeerConfig{}, nil)
	assert.Error(t, err)

	err = s.AddPeer(PeerConfig{
		LocalAddress:  netip.MustParseAddr("::1"),
		RemoteAddress: netip.MustParseAddr("127.0.0.2"),
		LocalAS:       64512,
		RemoteAS:      64513,
	}, nil)
	assert.Error(t, err)

	pcIPv4 := PeerConfig{
		LocalAddress:  netip.MustParseAddr("127.0.0.1"),
		RemoteAddress: netip.MustParseAddr("127.0.0.2"),
		LocalAS:       64512,
		RemoteAS:      64513,
	}
	err = s.AddPeer(pcIPv4, nil)
	assert.NoError(t, err)
	err = s.AddPeer(pcIPv4, nil)
	assert.ErrorIs(t, err, ErrPeerAlreadyExists)

	pcIPv6 := PeerConfig{
		LocalAddress:  netip.MustParseAddr("::1"),
		RemoteAddress: netip.MustParseAddr("::2"),
		LocalAS:       64512,
		RemoteAS:      64513,
	}
	err = s.AddPeer(pcIPv6, nil)
	assert.NoError(t, err)
	err = s.AddPeer(pcIPv6, nil)
	assert.ErrorIs(t, err, ErrPeerAlreadyExists)

	pcs := s.ListPeers()
	if assert.Len(t, pcs, 2) {
		var found [2]bool
		for _, pc := range pcs {
			if reflect.DeepEqual(pc, pcIPv4) {
				found[0] = true
			}
			if reflect.DeepEqual(pc, pcIPv6) {
				found[1] = true
			}
		}
		assert.True(t, found[0])
		assert.True(t, found[1])
	}

	err = s.DeletePeer(pcIPv4.RemoteAddress)
	assert.NoError(t, err)
	err = s.DeletePeer(pcIPv4.RemoteAddress)
	assert.ErrorIs(t, err, ErrPeerNotExist)
}
