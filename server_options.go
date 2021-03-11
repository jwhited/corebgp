package corebgp

import (
	"fmt"
	"net"
)

type serverOptions struct {
	localAddrs map[string]struct{}
}

func (s serverOptions) validate() error {
	for laddr := range s.localAddrs {
		host, _, err := net.SplitHostPort(laddr)
		if err != nil {
			return fmt.Errorf("invalid local addr (%s): %v", laddr, err)
		}
		if net.ParseIP(host) == nil {
			return fmt.Errorf("invalid IP address in laddr: %s", host)
		}
	}
	return nil
}

type ServerOption interface {
	apply(*serverOptions)
}

func defaultServerOptions() serverOptions {
	return serverOptions{
		localAddrs: make(map[string]struct{}),
	}
}

type funcServerOption struct {
	fn func(*serverOptions)
}

func (f *funcServerOption) apply(p *serverOptions) {
	f.fn(p)
}

func newFuncServerOptions(f func(*serverOptions)) *funcServerOption {
	return &funcServerOption{
		fn: f,
	}
}

// LocalAddrs returns a ServerOption to set the local addresses the server
// should bind to in addr:port form where addr is a literal IP address. IPv6
// addresses must be enclosed in square brackets, e.g. '[::]:179'.
func LocalAddrs(laddrs []string) ServerOption {
	return newFuncServerOptions(func(o *serverOptions) {
		for _, laddr := range laddrs {
			o.localAddrs[laddr] = struct{}{}
		}
	})
}
