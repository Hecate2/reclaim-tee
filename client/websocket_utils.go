package client

import (
	"context"
	"net"

	"github.com/gorilla/websocket"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func installWebSocketReadLimit(conn *websocket.Conn) {
	conn.SetReadLimit(shared.MaxWebSocketMessageSize)
}

// createNativeNetworkDialer creates a WebSocket dialer that uses native networking
// for iOS VPN compatibility. The dialer uses a custom NetDialTLSContext that
// delegates connection establishment to the native iOS/Flutter layer.
func createNativeNetworkDialer(targetURL string, timeoutMs int) *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: DefaultWSHandshakeTimeout,
		// NetDialTLSContext is used for wss:// connections.
		// When set, the Dialer assumes TLS handshake is done by this function.
		//
		// Note: The ctx parameter is intentionally not used here because the native
		// iOS VPN bridge (NativeDialWebSocket) only accepts a timeout in milliseconds.
		// Context cancellation/deadline propagation is not supported by the native API.
		// The timeoutMs parameter provides equivalent timeout functionality.
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_ = ctx // ctx intentionally unused - native bridge uses timeoutMs instead
			return NativeDialWebSocket(targetURL, timeoutMs)
		},
		// NetDialContext is used for ws:// connections.
		//
		// Note: The ctx parameter is intentionally not used here because the native
		// iOS VPN bridge (NativeDialWebSocket) only accepts a timeout in milliseconds.
		// Context cancellation/deadline propagation is not supported by the native API.
		// The timeoutMs parameter provides equivalent timeout functionality.
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_ = ctx // ctx intentionally unused - native bridge uses timeoutMs instead
			return NativeDialWebSocket(targetURL, timeoutMs)
		},
	}
}
