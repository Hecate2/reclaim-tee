package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

// vsockDialFunc is a variable function for vsock.Dial that can be mocked in tests
var vsockDialFunc = func(cid, port uint32) (net.Conn, error) {
	return vsock.Dial(cid, port, nil)
}

type HTTPSRouter struct {
	config *ProxyConfig
	logger *zap.Logger
}

func NewHTTPSRouter(config *ProxyConfig, logger *zap.Logger) (*HTTPSRouter, error) {
	return &HTTPSRouter{
		config: config,
		logger: logger.With(zap.String("component", "https_router")),
	}, nil
}

func (r *HTTPSRouter) Start(ctx context.Context, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", port, err)
	}
	defer listener.Close()

	r.logger.Info("HTTPS router started", zap.Int("port", port))

	// Channel for accepting connections
	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	// Accept connections in separate goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case errChan <- err:
				case <-ctx.Done():
					return
				}
				return
			}
			select {
			case connChan <- conn:
			case <-ctx.Done():
				conn.Close()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("HTTPS router shutting down")
			return nil
		case err := <-errChan:
			r.logger.Error("Accept error", zap.Error(err))
			return err
		case conn := <-connChan:
			go r.handleConnection(ctx, conn)
		}
	}
}

func (r *HTTPSRouter) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Set read timeout for SNI extraction
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Extract SNI from TLS ClientHello and get the connection that preserves all data
	sni, replayConn, err := r.extractSNIWithReplay(conn)
	if err != nil {
		return
	}

	if sni == "" {
		return
	}

	r.logger.Info("Routing HTTPS connection", zap.String("sni", sni))

	// Find target enclave based on SNI
	var targetCID uint32
	var found bool
	for domain, target := range r.config.Domains {
		if strings.Contains(sni, domain) || sni == domain {
			targetCID = target.CID
			found = true
			break
		}
	}

	if !found {
		return
	}

	// Connect to target enclave
	enclaveConn, err := vsockDialFunc(targetCID, 8443)
	if err != nil {
		r.logger.Error("Failed to connect to enclave",
			zap.Uint32("cid", targetCID),
			zap.Error(err))
		return
	}
	defer enclaveConn.Close()

	// Clear read deadline and start bidirectional copy
	replayConn.SetReadDeadline(time.Time{})

	// Set reasonable timeouts for long-lived connections
	deadline := time.Now().Add(5 * time.Minute)
	replayConn.SetDeadline(deadline)
	enclaveConn.SetDeadline(deadline)

	// Bidirectional copy between client and enclave using the replay connection
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(enclaveConn, replayConn) // Use replayConn instead of conn
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(replayConn, enclaveConn) // Use replayConn instead of conn
	}()

	// Wait for either copy to complete or context cancellation
	select {
	case <-done:
		// Connection completed
	case <-ctx.Done():
		// Context cancelled
	case <-time.After(5 * time.Minute):
		// Long timeout for persistent connections
		r.logger.Info("HTTPS connection timeout", zap.String("sni", sni))
	}
}

// extractSNIWithReplay extracts SNI and returns a connection that can replay all data
func (r *HTTPSRouter) extractSNIWithReplay(conn net.Conn) (string, net.Conn, error) {
	// Use a buffered approach that can handle fragmented TLS records
	reader := &tlsRecordReader{conn: conn}

	// Read the complete TLS ClientHello record
	record, err := reader.readCompleteTLSRecord()
	if err != nil {
		return "", nil, fmt.Errorf("failed to read TLS record: %v", err)
	}

	// Extract SNI from the complete record
	sni, err := r.extractSNIFromBytes(record)
	if err != nil {
		return "", nil, fmt.Errorf("failed to extract SNI: %v", err)
	}

	// Create replay connection with all consumed data
	replayConn := &combinedConn{
		Conn:   conn,
		buffer: reader.consumedBytes,
		offset: 0,
	}

	return sni, replayConn, nil
}

// tlsRecordReader helps read complete TLS records while tracking consumed bytes
type tlsRecordReader struct {
	conn          net.Conn
	consumedBytes []byte
}

func (r *tlsRecordReader) readCompleteTLSRecord() ([]byte, error) {
	// Read TLS record header (5 bytes)
	header := make([]byte, 5)
	_, err := io.ReadFull(r.conn, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS record header: %v", err)
	}
	r.consumedBytes = append(r.consumedBytes, header...)

	// Check if it's a handshake record (type 22)
	if header[0] != 22 {
		return nil, fmt.Errorf("not a TLS handshake record: type %d", header[0])
	}

	// Extract record length from header
	recordLength := int(header[3])<<8 | int(header[4])

	// Read the complete record payload
	payload := make([]byte, recordLength)
	_, err = io.ReadFull(r.conn, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS record payload: %v", err)
	}
	r.consumedBytes = append(r.consumedBytes, payload...)

	// Return the complete record (header + payload)
	completeRecord := make([]byte, 5+recordLength)
	copy(completeRecord, header)
	copy(completeRecord[5:], payload)

	return completeRecord, nil
}

// extractSNIWithTLS uses TLS parsing to extract SNI (fallback method)
func (r *HTTPSRouter) extractSNIWithTLS(replayConn *combinedConn) (string, error) {
	// Parse TLS ClientHello to extract SNI
	config := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// This callback is called with the parsed ClientHello
			// We just need the SNI, so we can return an error to stop the handshake
			return nil, fmt.Errorf("SNI extraction complete")
		},
	}

	// Attempt to start TLS handshake to trigger SNI parsing
	// Note: We intentionally don't close tlsConn as that would close the underlying connection
	tlsConn := tls.Server(replayConn, config)
	_ = tlsConn.Handshake() // Ignore error - we expect this to fail during SNI extraction

	// The handshake will fail, but we should have captured the SNI
	if hello := tlsConn.ConnectionState().ServerName; hello != "" {
		return hello, nil
	}

	return "", fmt.Errorf("failed to extract SNI via TLS parsing")
}

func (r *HTTPSRouter) extractSNI(conn net.Conn) (string, error) {
	// Read enough bytes to capture the TLS ClientHello
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("failed to read TLS data: %v", err)
	}

	// Create a new connection that includes the read data
	combinedConn := &combinedConn{
		Conn:   conn,
		buffer: buf[:n],
		offset: 0,
	}

	// Parse TLS ClientHello to extract SNI
	config := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// This callback is called with the parsed ClientHello
			// We just need the SNI, so we can return an error to stop the handshake
			return nil, fmt.Errorf("SNI extraction complete")
		},
	}

	// Attempt to start TLS handshake to trigger SNI parsing
	// Note: We intentionally don't close tlsConn as that would close the underlying connection
	tlsConn := tls.Server(combinedConn, config)
	err = tlsConn.Handshake()

	// The handshake will fail, but we should have captured the SNI
	if hello := tlsConn.ConnectionState().ServerName; hello != "" {
		return hello, nil
	}

	// Fallback: manual SNI extraction from raw TLS data
	return r.extractSNIFromBytes(buf[:n])
}

func (r *HTTPSRouter) extractSNIFromBytes(data []byte) (string, error) {
	// This is a simplified SNI parser for TLS ClientHello
	// TLS Record format: [type(1)] [version(2)] [length(2)] [payload]
	if len(data) < 43 {
		return "", fmt.Errorf("TLS data too short")
	}

	// Check if it's a TLS handshake record (type 22)
	if data[0] != 22 {
		return "", fmt.Errorf("not a TLS handshake record")
	}

	// Skip TLS record header (5 bytes) and handshake header (4 bytes)
	// ClientHello: [msg_type(1)] [length(3)] [version(2)] [random(32)] [session_id_length(1)]
	offset := 5 + 4 + 2 + 32 + 1

	if len(data) <= offset {
		return "", fmt.Errorf("TLS ClientHello too short")
	}

	// Skip session ID
	sessionIDLength := int(data[offset-1])
	offset += sessionIDLength

	if len(data) <= offset+2 {
		return "", fmt.Errorf("TLS ClientHello incomplete")
	}

	// Skip cipher suites
	cipherSuitesLength := int(data[offset])<<8 + int(data[offset+1])
	offset += 2 + cipherSuitesLength

	if len(data) <= offset+1 {
		return "", fmt.Errorf("TLS ClientHello incomplete")
	}

	// Skip compression methods
	compressionMethodsLength := int(data[offset])
	offset += 1 + compressionMethodsLength

	if len(data) <= offset+2 {
		return "", fmt.Errorf("no extensions in ClientHello")
	}

	// Parse extensions
	extensionsLength := int(data[offset])<<8 + int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLength
	for offset < extensionsEnd && offset+4 <= len(data) {
		extType := int(data[offset])<<8 + int(data[offset+1])
		extLength := int(data[offset+2])<<8 + int(data[offset+3])
		offset += 4

		if extType == 0 { // Server Name Indication extension
			if offset+extLength <= len(data) {
				return r.parseSNIExtension(data[offset : offset+extLength])
			}
		}

		offset += extLength
	}

	return "", fmt.Errorf("SNI extension not found")
}

func (r *HTTPSRouter) parseSNIExtension(extData []byte) (string, error) {
	if len(extData) < 5 {
		return "", fmt.Errorf("SNI extension too short")
	}

	// SNI extension format: [list_length(2)] [name_type(1)] [name_length(2)] [name]
	listLength := int(extData[0])<<8 + int(extData[1])
	if len(extData) < 2+listLength {
		return "", fmt.Errorf("SNI extension incomplete")
	}

	nameType := extData[2]
	if nameType != 0 { // hostname type
		return "", fmt.Errorf("unsupported name type: %d", nameType)
	}

	nameLength := int(extData[3])<<8 + int(extData[4])
	if len(extData) < 5+nameLength {
		return "", fmt.Errorf("SNI name incomplete")
	}

	return string(extData[5 : 5+nameLength]), nil
}

// combinedConn wraps a connection and prepends buffered data
type combinedConn struct {
	net.Conn
	buffer []byte
	offset int
}

func (c *combinedConn) Read(b []byte) (int, error) {
	if c.offset < len(c.buffer) {
		n := copy(b, c.buffer[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(b)
}
