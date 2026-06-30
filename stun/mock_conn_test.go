package stun

import (
	"net"
	"time"
)

type mockTimeoutError struct{}

func (e *mockTimeoutError) Error() string   { return "i/o timeout" }
func (e *mockTimeoutError) Timeout() bool   { return true }
func (e *mockTimeoutError) Temporary() bool { return true }

type writeRecord struct {
	data []byte
	addr net.Addr
}

type mockPacketConn struct {
	localAddr      net.Addr
	readBuf        chan []byte
	readAddr       chan net.Addr
	writeCalls     []writeRecord
	readDeadline   time.Time
	writeSignal    chan struct{}
	instantTimeout bool
}

func newMockPacketConn(local net.Addr) *mockPacketConn {
	return &mockPacketConn{
		localAddr:      local,
		readBuf:        make(chan []byte, 100),
		readAddr:       make(chan net.Addr, 100),
		writeCalls:     make([]writeRecord, 0),
		writeSignal:    make(chan struct{}, 100),
		instantTimeout: false,
	}
}

func (m *mockPacketConn) LocalAddr() net.Addr {
	return m.localAddr
}

func (m *mockPacketConn) Close() error {
	return nil
}

func (m *mockPacketConn) SetDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func (m *mockPacketConn) SetReadDeadline(t time.Time) error {
	m.readDeadline = t
	return nil
}

func (m *mockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	data := make([]byte, len(p))
	copy(data, p)
	m.writeCalls = append(m.writeCalls, writeRecord{data, addr})
	select {
	case m.writeSignal <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if m.instantTimeout {
		return 0, nil, &mockTimeoutError{}
	}

	var timeout <-chan time.Time
	if !m.readDeadline.IsZero() {
		dur := time.Until(m.readDeadline)
		if dur <= 0 {
			return 0, nil, &mockTimeoutError{}
		}
		timeout = time.After(dur)
	}

	select {
	case data := <-m.readBuf:
		copy(p, data)
		addr = <-m.readAddr
		return len(data), addr, nil
	case <-timeout:
		return 0, nil, &mockTimeoutError{}
	}
}
