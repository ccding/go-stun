package stun

import (
	"log"
	"os"
)

// StunLogger is a simple logger specified for this STUN client.
type StunLogger struct {
	log.Logger
	debug bool
}

// NewStunLogger creates a default logger.
func NewStunLogger() *StunLogger {
	logger := &StunLogger{*log.New(os.Stdout, "", log.LstdFlags), false}
	return logger
}

// SetDebug sets the logger running in debug mode or not.
func (l *StunLogger) SetDebug(debug bool) {
	l.debug = debug
}

// Debug outputs the log in the format of log.Print.
func (l *StunLogger) Debug(v ...interface{}) {
	if l.debug {
		l.Print(v...)
	}
}

// Debug outputs the log in the format of log.Printf.
func (l *StunLogger) Debugf(format string, v ...interface{}) {
	if l.debug {
		l.Printf(format, v...)
	}
}

// Debug outputs the log in the format of log.Println.
func (l *StunLogger) Debugln(v ...interface{}) {
	if l.debug {
		l.Println(v...)
	}
}
