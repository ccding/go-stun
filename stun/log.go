package stun

import (
	"log"
	"os"
)

// Logger is a simple logger specified for this STUN client.
type Logger struct {
	log.Logger
	debug bool
}

// NewLogger creates a default logger.
func NewLogger() *Logger {
	logger := &Logger{*log.New(os.Stdout, "", log.LstdFlags), false}
	return logger
}

// SetDebug sets the logger running in debug mode or not.
func (l *Logger) SetDebug(debug bool) {
	l.debug = debug
}

// Debug outputs the log in the format of log.Print.
func (l *Logger) Debug(v ...interface{}) {
	if l.debug {
		l.Print(v...)
	}
}

// Debugf outputs the log in the format of log.Printf.
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l.debug {
		l.Printf(format, v...)
	}
}

// Debugln outputs the log in the format of log.Println.
func (l *Logger) Debugln(v ...interface{}) {
	if l.debug {
		l.Println(v...)
	}
}
