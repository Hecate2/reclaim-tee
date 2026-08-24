package client

import (
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

type idleTimeoutTestError struct{}

func (idleTimeoutTestError) Error() string   { return "test read timeout" }
func (idleTimeoutTestError) Timeout() bool   { return true }
func (idleTimeoutTestError) Temporary() bool { return true }

type idleTimeoutTestConn struct {
	reads   atomic.Int32
	readErr error
	onRead  func(int32)
}

func (c *idleTimeoutTestConn) Read([]byte) (int, error) {
	read := c.reads.Add(1)
	if c.onRead != nil {
		c.onRead(read)
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return 0, idleTimeoutTestError{}
}

func (*idleTimeoutTestConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*idleTimeoutTestConn) Close() error                     { return nil }
func (*idleTimeoutTestConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*idleTimeoutTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*idleTimeoutTestConn) SetDeadline(time.Time) error      { return nil }
func (*idleTimeoutTestConn) SetReadDeadline(time.Time) error  { return nil }
func (*idleTimeoutTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPToWebsocketWaitsForFirstResponseBeyondIdleWindow(t *testing.T) {
	c := NewClient("")
	conn := &idleTimeoutTestConn{}
	conn.onRead = func(read int32) {
		if read == 6 {
			c.isClosing.Store(true)
		}
	}
	c.tcpConn = conn
	c.handshakeComplete.Store(true)
	c.httpRequestSent.Store(true)

	c.tcpToWebsocket()

	if got := conn.reads.Load(); got != 6 {
		t.Fatalf("TCP reads = %d, want 6; client treated pre-response silence as completed idle", got)
	}
	select {
	case err := <-c.WaitForCompletion():
		t.Fatalf("pre-response silence terminated the protocol: %v", err)
	default:
	}
}

func TestTCPToWebsocketFlushesAfterCapturedResponseIdle(t *testing.T) {
	c := NewClient("")
	conn := &idleTimeoutTestConn{}
	c.tcpConn = conn
	c.handshakeComplete.Store(true)
	c.httpRequestSent.Store(true)
	c.batchedResponses = append(c.batchedResponses, shared.EncryptedResponseData{})

	c.tcpToWebsocket()

	if got := conn.reads.Load(); got != 5 {
		t.Fatalf("TCP reads = %d, want 5 before post-response idle flush", got)
	}
	select {
	case err := <-c.WaitForCompletion():
		if err == nil || !strings.Contains(err.Error(), "Failed to send batched responses") {
			t.Fatalf("post-response idle result = %v, want batch-send attempt", err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-response idle did not flush the captured response")
	}
}

func TestTCPToWebsocketFailsImmediatelyOnEOFBeforeFirstResponse(t *testing.T) {
	c := NewClient("")
	conn := &idleTimeoutTestConn{readErr: io.EOF}
	c.tcpConn = conn
	c.handshakeComplete.Store(true)
	c.httpRequestSent.Store(true)

	c.tcpToWebsocket()

	if got := conn.reads.Load(); got != 1 {
		t.Fatalf("TCP reads = %d, want one read before EOF failure", got)
	}
	select {
	case err := <-c.WaitForCompletion():
		if err == nil || !strings.Contains(err.Error(), "Target server returned no response data") {
			t.Fatalf("EOF result = %v, want no-response failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("EOF before first response did not terminate the protocol")
	}
}
