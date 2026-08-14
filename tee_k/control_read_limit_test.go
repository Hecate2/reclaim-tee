package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/gorilla/websocket"
)

func TestDialControlConnectionInstallsReadLimitBeforeReturn(t *testing.T) {
	for _, tc := range []struct {
		name      string
		size      int
		wantLimit bool
	}{
		{name: "at limit", size: MaxWebSocketMessageSize},
		{name: "one byte over", size: MaxWebSocketMessageSize + 1, wantLimit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientNet, peerNet := net.Pipe()
			t.Cleanup(func() {
				_ = clientNet.Close()
				_ = peerNet.Close()
			})
			go serveReadLimitTestWebSocket(peerNet, tc.size)
			dialer := &websocket.Dialer{
				NetDial: func(_, _ string) (net.Conn, error) {
					return clientNet, nil
				},
			}
			conn, err := dialWebSocketWithReadLimit(dialer, "ws://in-memory/control", MaxWebSocketMessageSize)
			if err != nil {
				t.Fatalf("dial control connection: %v", err)
			}
			defer conn.Close()

			_, payload, err := conn.ReadMessage()
			if tc.wantLimit {
				if err == nil || err != websocket.ErrReadLimit {
					t.Fatalf("read over limit error = %v, want read limit exceeded", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("read at limit: %v", err)
			}
			if len(payload) != tc.size {
				t.Fatalf("payload size = %d, want %d", len(payload), tc.size)
			}
		})
	}
}

func serveReadLimitTestWebSocket(peer net.Conn, payloadSize int) {
	reader := bufio.NewReader(peer)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	sum := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if _, err := fmt.Fprintf(peer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		return
	}
	header := []byte{0x80 | websocket.BinaryMessage, 127}
	var extended [8]byte
	binary.BigEndian.PutUint64(extended[:], uint64(payloadSize))
	if _, err := peer.Write(append(header, extended[:]...)); err != nil {
		return
	}
	_, _ = io.CopyN(peer, zeroReader{}, int64(payloadSize))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
