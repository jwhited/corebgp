package corebgp

import "fmt"

// Logger is a log.Print-compatible function
type Logger func(...interface{})

var (
	defaultLogger Logger = nil
)

// SetDefaultLogger sets the default logger for all instances
// of a corebgp server. Passing the WithLogger option to the server
// constructor is preferred as this is function is maintained for
// backwards compatibility.
func SetLogger(l Logger) {
	defaultLogger = l
}

func (l Logger) log(v ...interface{}) {
	if l != nil {
		l(v...)
	}
}

func (l Logger) logf(format string, v ...interface{}) {
	l.log(fmt.Sprintf(format, v...))
}
