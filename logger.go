package corebgp

import (
	"fmt"
)

// Logger is a log.Print-compatible function
type Logger func(...interface{})

var (
	logger      Logger = nil
)

// SetLogger enables logging with the provided Logger.
func SetLogger(l Logger) {
	logger = l
}

func log(v ...interface{}) {
	if logger != nil {
		logger(v...)
	}
}

func logf(format string, v ...interface{}) {
	log(fmt.Sprintf(format, v...))
}
