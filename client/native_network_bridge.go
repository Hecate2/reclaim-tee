package client

import (
	"net"
	"sync"
)

// Native network function types for bridging lib -> client packages
type (
	// NativeNetworkCheckFunc checks if native networking is enabled
	NativeNetworkCheckFunc func() bool

	// NativeDialWebSocketFunc dials a WebSocket connection via native networking
	NativeDialWebSocketFunc func(url string, timeoutMs int) (net.Conn, error)

	// NativeDialTCPFunc dials a TCP connection via native networking
	NativeDialTCPFunc func(address string, timeoutMs int) (net.Conn, error)
)

// Native network bridge state
var (
	nativeBridgeMutex       sync.RWMutex
	nativeNetworkCheckFunc  NativeNetworkCheckFunc
	nativeDialWebSocketFunc NativeDialWebSocketFunc
	nativeDialTCPFunc       NativeDialTCPFunc
)

// SetNativeNetworkFunctions registers the native network functions from the lib package
// This allows the client package to use native networking without circular imports
func SetNativeNetworkFunctions(
	checkFunc NativeNetworkCheckFunc,
	wsDialFunc NativeDialWebSocketFunc,
	tcpDialFunc NativeDialTCPFunc,
) {
	nativeBridgeMutex.Lock()
	defer nativeBridgeMutex.Unlock()

	nativeNetworkCheckFunc = checkFunc
	nativeDialWebSocketFunc = wsDialFunc
	nativeDialTCPFunc = tcpDialFunc
}

// IsNativeNetworkingEnabled checks if native networking is enabled and available
func IsNativeNetworkingEnabled() bool {
	nativeBridgeMutex.RLock()
	checkFunc := nativeNetworkCheckFunc
	nativeBridgeMutex.RUnlock()

	if checkFunc == nil {
		return false
	}
	return checkFunc()
}

// NativeDialWebSocket creates a WebSocket connection via native networking
// Returns an error if native networking is not enabled or not configured
func NativeDialWebSocket(url string, timeoutMs int) (net.Conn, error) {
	nativeBridgeMutex.RLock()
	dialFunc := nativeDialWebSocketFunc
	nativeBridgeMutex.RUnlock()

	if dialFunc == nil {
		return nil, ErrNativeNetworkNotConfigured
	}
	return dialFunc(url, timeoutMs)
}

// NativeDialTCP creates a TCP connection via native networking
// Returns an error if native networking is not enabled or not configured
func NativeDialTCP(address string, timeoutMs int) (net.Conn, error) {
	nativeBridgeMutex.RLock()
	dialFunc := nativeDialTCPFunc
	nativeBridgeMutex.RUnlock()

	if dialFunc == nil {
		return nil, ErrNativeNetworkNotConfigured
	}
	return dialFunc(address, timeoutMs)
}
