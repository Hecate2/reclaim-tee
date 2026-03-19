package main

/*
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

// Native connection handle - opaque pointer managed by iOS/Flutter
typedef void* native_conn_handle_t;

// Connection types
typedef enum {
    CONN_TYPE_WEBSOCKET = 1,
    CONN_TYPE_TCP = 2
} connection_type_t;

// Error codes for native network operations
typedef enum {
    NATIVE_NET_SUCCESS = 0,
    NATIVE_NET_ERROR_UNKNOWN = -1,
    NATIVE_NET_ERROR_TIMEOUT = -2,
    NATIVE_NET_ERROR_EOF = -3,
    NATIVE_NET_ERROR_CLOSED = -4,
    NATIVE_NET_ERROR_CONNECT_FAILED = -5
} native_net_error_t;

// Result of a connection attempt
typedef struct {
    native_conn_handle_t handle;
    int error_code;
    const char* error_message;
} connection_result_t;

// Result of a read operation
typedef struct {
    const unsigned char* data;
    int length;
    int error_code;
} read_result_t;

// Callback function types (Async)
// Note: Native callbacks must synchronously copy all inputs before returning.
typedef void (*native_connect_cb_t)(int64_t req_id, int conn_type, const char* url, int timeout_ms);
typedef void (*native_read_cb_t)(int64_t req_id, native_conn_handle_t handle, int max_bytes, int timeout_ms);
typedef void (*native_write_cb_t)(int64_t req_id, native_conn_handle_t handle, const unsigned char* data, int length);
typedef void (*native_close_cb_t)(native_conn_handle_t handle);

// Global callback storage
static native_connect_cb_t g_native_connect_cb = NULL;
static native_read_cb_t g_native_read_cb = NULL;
static native_write_cb_t g_native_write_cb = NULL;
static native_close_cb_t g_native_close_cb = NULL;

// Store callbacks
static inline void store_native_connect_cb(native_connect_cb_t cb) {
    g_native_connect_cb = cb;
}
static inline void store_native_read_cb(native_read_cb_t cb) {
    g_native_read_cb = cb;
}
static inline void store_native_write_cb(native_write_cb_t cb) {
    g_native_write_cb = cb;
}
static inline void store_native_close_cb(native_close_cb_t cb) {
    g_native_close_cb = cb;
}

// Call the connect callback
static inline void call_native_connect_async(int64_t req_id, int conn_type, const char* url, int timeout_ms) {
    if (g_native_connect_cb != NULL) {
        g_native_connect_cb(req_id, conn_type, url, timeout_ms);
    }
}

// Call the read callback
static inline void call_native_read_async(int64_t req_id, native_conn_handle_t handle, int max_bytes, int timeout_ms) {
    if (g_native_read_cb != NULL) {
        g_native_read_cb(req_id, handle, max_bytes, timeout_ms);
    }
}

// Call the write callback
static inline void call_native_write_async(int64_t req_id, native_conn_handle_t handle, const unsigned char* data, int length) {
    if (g_native_write_cb != NULL) {
        g_native_write_cb(req_id, handle, data, length);
    }
}

// Call the close callback
static inline void call_native_close(native_conn_handle_t handle) {
    if (g_native_close_cb != NULL) {
        g_native_close_cb(handle);
    }
}
*/
import "C"
import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/reclaimprotocol/reclaim-tee/client"
	"go.uber.org/zap"
)

// Error variables for native network operations
var (
	ErrNativeNetworkNotEnabled = errors.New("native networking not enabled")
	ErrNativeConnectionClosed  = errors.New("native connection closed")
	ErrNativeNetworkTimeout    = errors.New("native network operation timed out")
	ErrNativeConnectFailed     = errors.New("native connection failed")
)

// Thread-safe state for native networking (following flutter_logger.go pattern)
var (
	nativeNetworkMutex   sync.RWMutex
	nativeNetworkEnabled bool = false
	activeConnections    int32
	pendingDisable       bool

	// Request tracking for async callbacks
	reqIDCounter   int64
	reqMutex       sync.RWMutex
	pendingReqs    = make(map[int64]chan interface{})
	pendingCAllocs = make(map[int64]unsafe.Pointer)
)

func generateReqID() int64 {
	return atomic.AddInt64(&reqIDCounter, 1)
}

func registerReq(reqID int64, ch chan interface{}, alloc unsafe.Pointer) {
	reqMutex.Lock()
	pendingReqs[reqID] = ch
	if alloc != nil {
		pendingCAllocs[reqID] = alloc
	}
	reqMutex.Unlock()
}

func unregisterReq(reqID int64) {
	reqMutex.Lock()
	delete(pendingReqs, reqID)
	reqMutex.Unlock()
}

func completeReq(reqID int64, result interface{}) {
	reqMutex.Lock()
	if ptr, ok := pendingCAllocs[reqID]; ok && ptr != nil {
		C.free(ptr)
		delete(pendingCAllocs, reqID)
	}
	ch, ok := pendingReqs[reqID]
	reqMutex.Unlock()

	if ok {
		select {
		case ch <- result:
		default:
		}
	}
}

type connectResultStruct struct {
	res C.connection_result_t
	msg string
}

type readResultStruct struct {
	data []byte
	err  C.int
}

type writeResultStruct struct {
	written C.int
	err     C.int
}

//export submit_connect_result
func submit_connect_result(req_id C.int64_t, handle C.native_conn_handle_t, err_code C.int, err_msg *C.char) {
	var errMsg string
	if err_msg != nil {
		errMsg = C.GoString(err_msg)
	}
	result := C.connection_result_t{
		handle:     handle,
		error_code: err_code,
	}
	completeReq(int64(req_id), connectResultStruct{result, errMsg})
}

//export submit_read_result
func submit_read_result(req_id C.int64_t, data *C.uchar, length C.int, err_code C.int) {
	var slice []byte
	if length > 0 && data != nil {
		slice = C.GoBytes(unsafe.Pointer(data), length)
	}
	completeReq(int64(req_id), readResultStruct{slice, err_code})
}

//export submit_write_result
func submit_write_result(req_id C.int64_t, bytes_written C.int, err_code C.int) {
	completeReq(int64(req_id), writeResultStruct{bytes_written, err_code})
}

// DelegatedConn wraps a native connection handle and implements net.Conn
type DelegatedConn struct {
	handle     C.native_conn_handle_t
	connType   C.connection_type_t
	remoteAddr string
	localAddr  string

	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closeMutex sync.RWMutex
	closed     int32 // atomic flag

	// Buffered read data for partial reads
	readBuffer []byte
}

// Ensure DelegatedConn implements net.Conn
var _ net.Conn = (*DelegatedConn)(nil)

// newDelegatedConn creates a new DelegatedConn wrapping a native handle
func newDelegatedConn(handle C.native_conn_handle_t, connType C.connection_type_t, remoteAddr string) *DelegatedConn {
	return &DelegatedConn{
		handle:     handle,
		connType:   connType,
		remoteAddr: remoteAddr,
		localAddr:  "native:0",
	}
}

// Read implements net.Conn.Read
func (c *DelegatedConn) Read(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, ErrNativeConnectionClosed
	}

	// Handle zero-length buffer per io.Reader semantics
	if len(b) == 0 {
		return 0, nil
	}

	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	// Return buffered data first if available
	if len(c.readBuffer) > 0 {
		n := copy(b, c.readBuffer)
		c.readBuffer = c.readBuffer[n:]
		return n, nil
	}

	c.closeMutex.RLock()
	if atomic.LoadInt32(&c.closed) == 1 {
		c.closeMutex.RUnlock()
		return 0, ErrNativeConnectionClosed
	}

	// Call native read callback via async request ID
	reqID := generateReqID()
	ch := make(chan interface{}, 1)
	registerReq(reqID, ch, nil)

	C.call_native_read_async(C.int64_t(reqID), c.handle, C.int(len(b)), C.int(30000))
	c.closeMutex.RUnlock()
	defer unregisterReq(reqID)

	var readRes readResultStruct
	select {
	case resIntf := <-ch:
		readRes = resIntf.(readResultStruct)
	case <-time.After(35 * time.Second): // Safety fallback
		return 0, ErrNativeNetworkTimeout
	}

	switch readRes.err {
	case C.NATIVE_NET_SUCCESS:
		if len(readRes.data) <= 0 {
			return 0, io.EOF
		}

		n := copy(b, readRes.data)
		if n < len(readRes.data) {
			c.readBuffer = append(c.readBuffer, readRes.data[n:]...)
		}
		return n, nil

	case C.NATIVE_NET_ERROR_EOF:
		return 0, io.EOF

	case C.NATIVE_NET_ERROR_TIMEOUT:
		return 0, ErrNativeNetworkTimeout

	case C.NATIVE_NET_ERROR_CLOSED:
		atomic.StoreInt32(&c.closed, 1)
		return 0, ErrNativeConnectionClosed

	default:
		return 0, fmt.Errorf("native read error: code %d", readRes.err)
	}
}

// Write implements net.Conn.Write
func (c *DelegatedConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) == 1 {
		return 0, ErrNativeConnectionClosed
	}

	// Handle zero-length buffer per io.Writer semantics
	if len(b) == 0 {
		return 0, nil
	}

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	c.closeMutex.RLock()
	if atomic.LoadInt32(&c.closed) == 1 {
		c.closeMutex.RUnlock()
		return 0, ErrNativeConnectionClosed
	}

	// Call native write callback
	reqID := generateReqID()
	ch := make(chan interface{}, 1)

	cData := C.CBytes(b)
	registerReq(reqID, ch, cData)

	C.call_native_write_async(C.int64_t(reqID), c.handle, (*C.uchar)(cData), C.int(len(b)))
	c.closeMutex.RUnlock()
	defer unregisterReq(reqID)

	var writeRes writeResultStruct
	select {
	case resIntf := <-ch:
		writeRes = resIntf.(writeResultStruct)
	case <-time.After(35 * time.Second):
		return 0, ErrNativeNetworkTimeout
	}

	if writeRes.err < 0 {
		switch writeRes.err {
		case C.NATIVE_NET_ERROR_CLOSED:
			atomic.StoreInt32(&c.closed, 1)
			return 0, ErrNativeConnectionClosed
		case C.NATIVE_NET_ERROR_TIMEOUT:
			return 0, ErrNativeNetworkTimeout
		default:
			return 0, fmt.Errorf("native write error: code %d", writeRes.err)
		}
	}

	if int(writeRes.written) < len(b) {
		return int(writeRes.written), io.ErrShortWrite
	}

	return int(writeRes.written), nil
}

// Close implements net.Conn.Close
func (c *DelegatedConn) Close() error {
	// Use atomic compare-and-swap for idempotent close
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil // Already closed
	}

	c.closeMutex.Lock()
	C.call_native_close(c.handle)
	c.closeMutex.Unlock()

	decrementActiveConnections()
	return nil
}

// LocalAddr implements net.Conn.LocalAddr
func (c *DelegatedConn) LocalAddr() net.Addr {
	return &nativeAddr{network: "native", address: c.localAddr}
}

// RemoteAddr implements net.Conn.RemoteAddr
func (c *DelegatedConn) RemoteAddr() net.Addr {
	return &nativeAddr{network: "native", address: c.remoteAddr}
}

// SetDeadline implements net.Conn.SetDeadline
func (c *DelegatedConn) SetDeadline(t time.Time) error {
	// Deadlines are handled per-operation via timeouts in native callbacks
	return nil
}

// SetReadDeadline implements net.Conn.SetReadDeadline
func (c *DelegatedConn) SetReadDeadline(t time.Time) error {
	// Deadlines are handled per-operation via timeouts in native callbacks
	return nil
}

// SetWriteDeadline implements net.Conn.SetWriteDeadline
func (c *DelegatedConn) SetWriteDeadline(t time.Time) error {
	// Deadlines are handled per-operation via timeouts in native callbacks
	return nil
}

// nativeAddr implements net.Addr for native connections
type nativeAddr struct {
	network string
	address string
}

func (a *nativeAddr) Network() string { return a.network }
func (a *nativeAddr) String() string  { return a.address }

// EnableNativeNetworking registers native network callbacks
//
//export enable_native_networking
func enable_native_networking(
	connectCb C.native_connect_cb_t,
	readCb C.native_read_cb_t,
	writeCb C.native_write_cb_t,
	closeCb C.native_close_cb_t,
) C.int {
	nativeNetworkMutex.Lock()
	defer nativeNetworkMutex.Unlock()

	if connectCb == nil || readCb == nil || writeCb == nil || closeCb == nil {
		if logger != nil {
			logger.Warn("enable_native_networking called with nil callback(s)")
		}
		return 0
	}

	C.store_native_connect_cb(connectCb)
	C.store_native_read_cb(readCb)
	C.store_native_write_cb(writeCb)
	C.store_native_close_cb(closeCb)
	nativeNetworkEnabled = true
	pendingDisable = false

	if logger != nil {
		logger.Info("Native networking enabled for VPN compatibility")
	}

	return 1
}

// DisableNativeNetworking unregisters native network callbacks
//
//export disable_native_networking
func disable_native_networking() {
	nativeNetworkMutex.Lock()
	defer nativeNetworkMutex.Unlock()

	nativeNetworkEnabled = false

	if atomic.LoadInt32(&activeConnections) == 0 {
		C.store_native_connect_cb(nil)
		C.store_native_read_cb(nil)
		C.store_native_write_cb(nil)
		C.store_native_close_cb(nil)
		pendingDisable = false
	} else {
		pendingDisable = true
	}

	if logger != nil {
		logger.Info("Native networking disabled")
	}
}

func decrementActiveConnections() {
	if atomic.AddInt32(&activeConnections, -1) == 0 {
		nativeNetworkMutex.Lock()
		defer nativeNetworkMutex.Unlock()
		if pendingDisable && atomic.LoadInt32(&activeConnections) == 0 {
			C.store_native_connect_cb(nil)
			C.store_native_read_cb(nil)
			C.store_native_write_cb(nil)
			C.store_native_close_cb(nil)
			pendingDisable = false
		}
	}
}

// IsNativeNetworkingAvailable checks if native networking is enabled
func IsNativeNetworkingAvailable() bool {
	nativeNetworkMutex.RLock()
	defer nativeNetworkMutex.RUnlock()
	return nativeNetworkEnabled
}

// NativeDialWebSocket creates a WebSocket connection via native networking
func NativeDialWebSocket(url string, timeoutMs int) (net.Conn, error) {
	nativeNetworkMutex.RLock()
	enabled := nativeNetworkEnabled
	if enabled {
		atomic.AddInt32(&activeConnections, 1)
	}
	nativeNetworkMutex.RUnlock()

	if !enabled {
		return nil, ErrNativeNetworkNotEnabled
	}

	success := false
	defer func() {
		if !success {
			decrementActiveConnections()
		}
	}()

	cURL := C.CString(url)

	reqID := generateReqID()
	ch := make(chan interface{}, 1)
	registerReq(reqID, ch, unsafe.Pointer(cURL))
	defer unregisterReq(reqID)

	C.call_native_connect_async(C.int64_t(reqID), C.CONN_TYPE_WEBSOCKET, cURL, C.int(timeoutMs))

	var connRes connectResultStruct
	select {
	case resIntf := <-ch:
		connRes = resIntf.(connectResultStruct)
	case <-time.After(time.Duration(timeoutMs+5000) * time.Millisecond):
		return nil, ErrNativeNetworkTimeout
	}

	result := connRes.res
	if result.error_code != C.NATIVE_NET_SUCCESS {
		errMsg := "connection failed"
		if connRes.msg != "" {
			errMsg = connRes.msg
		}
		if result.error_code == C.NATIVE_NET_ERROR_TIMEOUT {
			return nil, fmt.Errorf("%w: %s (code: %d)", ErrNativeNetworkTimeout, errMsg, result.error_code)
		}
		return nil, fmt.Errorf("%w: %s (code: %d)", ErrNativeConnectFailed, errMsg, result.error_code)
	}

	if result.handle == nil {
		return nil, fmt.Errorf("%w: nil handle returned", ErrNativeConnectFailed)
	}

	success = true
	return newDelegatedConn(result.handle, C.CONN_TYPE_WEBSOCKET, url), nil
}

// NativeDialTCP creates a TCP connection via native networking
func NativeDialTCP(address string, timeoutMs int) (net.Conn, error) {
	nativeNetworkMutex.RLock()
	enabled := nativeNetworkEnabled
	if enabled {
		atomic.AddInt32(&activeConnections, 1)
	}
	nativeNetworkMutex.RUnlock()

	if !enabled {
		return nil, ErrNativeNetworkNotEnabled
	}

	success := false
	defer func() {
		if !success {
			decrementActiveConnections()
		}
	}()

	cAddr := C.CString(address)

	reqID := generateReqID()
	ch := make(chan interface{}, 1)
	registerReq(reqID, ch, unsafe.Pointer(cAddr))
	defer unregisterReq(reqID)

	C.call_native_connect_async(C.int64_t(reqID), C.CONN_TYPE_TCP, cAddr, C.int(timeoutMs))

	var connRes connectResultStruct
	select {
	case resIntf := <-ch:
		connRes = resIntf.(connectResultStruct)
	case <-time.After(time.Duration(timeoutMs+5000) * time.Millisecond):
		return nil, ErrNativeNetworkTimeout
	}

	result := connRes.res
	if result.error_code != C.NATIVE_NET_SUCCESS {
		errMsg := "connection failed"
		if connRes.msg != "" {
			errMsg = connRes.msg
		}
		if result.error_code == C.NATIVE_NET_ERROR_TIMEOUT {
			return nil, fmt.Errorf("%w: %s (code: %d)", ErrNativeNetworkTimeout, errMsg, result.error_code)
		}
		return nil, fmt.Errorf("%w: %s (code: %d)", ErrNativeConnectFailed, errMsg, result.error_code)
	}

	if result.handle == nil {
		return nil, fmt.Errorf("%w: nil handle returned", ErrNativeConnectFailed)
	}

	success = true
	return newDelegatedConn(result.handle, C.CONN_TYPE_TCP, address), nil
}

// registerNativeNetworkBridge registers the native network functions with the client package
func registerNativeNetworkBridge() {
	client.SetNativeNetworkFunctions(
		IsNativeNetworkingAvailable,
		NativeDialWebSocket,
		NativeDialTCP,
	)
	if logger != nil {
		logger.Info("Native network bridge registered with client package",
			zap.String("source", "TEE-LIBRECLAIM"))
	}
}
