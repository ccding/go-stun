// Copyright 2016 Cong Ding
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stun

import (
	"log"
	"os"
)

// Logger is a simple logger specified for this STUN client.
type Logger struct {
	log.Logger
	debug bool
	info  bool
}

// NewLogger creates a default logger.
func NewLogger() *Logger {
	logger := &Logger{*log.New(os.Stdout, "", log.LstdFlags), false, false}
	return logger
}

// ready reports whether logging can proceed. Logger's zero value has no
// output writer, so install the package default lazily before calling the
// embedded log.Logger. A nil *Logger is treated as disabled.
func (l *Logger) ready(enabled bool) bool {
	if l == nil || !enabled {
		return false
	}
	if l.Writer() == nil {
		l.SetOutput(os.Stdout)
	}
	return true
}

// SetDebug sets the logger running in debug mode or not.
func (l *Logger) SetDebug(v bool) {
	if l == nil {
		return
	}
	l.debug = v
}

// SetInfo sets the logger running in info mode or not.
func (l *Logger) SetInfo(v bool) {
	if l == nil {
		return
	}
	l.info = v
}

// Debug outputs the log in the format of log.Print.
func (l *Logger) Debug(v ...interface{}) {
	if l != nil && l.ready(l.debug) {
		l.Print(v...)
	}
}

// Debugf outputs the log in the format of log.Printf.
func (l *Logger) Debugf(format string, v ...interface{}) {
	if l != nil && l.ready(l.debug) {
		l.Printf(format, v...)
	}
}

// Debugln outputs the log in the format of log.Println.
func (l *Logger) Debugln(v ...interface{}) {
	if l != nil && l.ready(l.debug) {
		l.Println(v...)
	}
}

// Info outputs the log in the format of log.Print.
func (l *Logger) Info(v ...interface{}) {
	if l != nil && l.ready(l.info) {
		l.Print(v...)
	}
}

// Infof outputs the log in the format of log.Printf.
func (l *Logger) Infof(format string, v ...interface{}) {
	if l != nil && l.ready(l.info) {
		l.Printf(format, v...)
	}
}

// Infoln outputs the log in the format of log.Println.
func (l *Logger) Infoln(v ...interface{}) {
	if l != nil && l.ready(l.info) {
		l.Println(v...)
	}
}
