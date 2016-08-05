package stun

import (
	"log"
	"os"
)

type StunLogger struct {
	log.Logger
	debug bool
}

func NewStunLogger() *StunLogger {
	logger := &StunLogger{*log.New(os.Stdout, "", log.LstdFlags), false}
	return logger
}

func (l *StunLogger) SetDebug(debug bool) {
	l.debug = debug
}

func (l *StunLogger) Debug(v ...interface{}) {
	if l.debug {
		l.Print(v...)
	}
}

func (l *StunLogger) Debugf(format string, v ...interface{}) {
	if l.debug {
		l.Printf(format, v...)
	}
}

func (l *StunLogger) Debugln(v ...interface{}) {
	if l.debug {
		l.Println(v...)
	}
}
