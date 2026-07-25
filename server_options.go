package corebgp

type ServerOption func(*Server)

// WithLogger returns a ServerOption that sets the logger for the server.
// This should be a log.Print-compatible function.
func WithLogger(l Logger) ServerOption {
	return func(s *Server) {
		s.logger = l
	}
}
