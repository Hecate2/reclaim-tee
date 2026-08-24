package client

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// activeResponseCaptures counts live TCP-capture loops across the process. A
// value >1 means overlapping capture goroutines (e.g. an SDK retry starting
// before the prior session's loop exits) — the condition behind cross-stream
// record corruption. Logged, not enforced.
var activeResponseCaptures atomic.Int64

// handleConnectionReady processes connection ready messages from TEE_K
func (c *Client) handleConnectionReady(msg *shared.Message) {
	var readyData shared.ConnectionReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		c.logger.Error("Failed to unmarshal connection ready data", zap.Error(err))
		return
	}

	if readyData.Success {
		// In Phase 2 split AEAD protocol, Client waits for handshake disclosure
		// then sends plaintext data to TEE_K for encryption
		// No direct TCP connection is established until we have encrypted data to send

		// Send TCP ready confirmation to TEE_K so it can start the handshake
		c.sendTCPReady()
	}
}

// sendTCPReady establishes TCP connection and sends ready message to TEE_K
func (c *Client) sendTCPReady() {

	// Establish TCP connection to website to act as proxy for TEE_K
	tcpAddr := net.JoinHostPort(c.targetHost, fmt.Sprintf("%d", c.targetPort))
	c.logger.Info("Attempting TCP connection", zap.String("addr", tcpAddr))

	var tcpConn net.Conn
	var err error

	// Check if native networking is enabled (for iOS VPN compatibility)
	if IsNativeNetworkingEnabled() {
		c.logger.Info("Using native networking for TCP (VPN compatibility)")
		tcpConn, err = NativeDialTCP(tcpAddr, 5000)
	} else if c.shouldUseProxy() {
		// Connect via BrightData proxy
		tcpConn, err = c.connectViaProxy(c.targetHost, c.targetPort)
	} else {
		// Direct connection
		d := net.Dialer{Timeout: time.Second * 5, Deadline: time.Now().Add(time.Second * 5)}
		tcpConn, err = d.Dial("tcp", tcpAddr)
	}

	c.logger.Info("TCP connection completed", zap.Bool("success", err == nil), zap.Bool("via_proxy", c.shouldUseProxy()))

	if err != nil {
		c.logger.Error("Failed to establish TCP connection to website", zap.Error(err))
		c.terminateConnectionWithError("TCP connection to target failed", err)
		return
	} else {
		c.tcpConn = tcpConn

		// Start proxying data from website back to TEE_K
		go c.tcpToWebsocket()
	}

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TcpReady{
			TcpReady: &teeproto.TCPReady{Success: true},
		},
	}

	if err = c.sendEnvelope(env); err != nil {
		c.logger.Error("Failed to send TCP ready message", zap.Error(err))
		c.terminateConnectionWithError("Failed to send TCP ready message", err)
	}
	c.logger.Info("TCP ready sent")
}

// handleSendTCPData processes send TCP data messages from TEE_K
func (c *Client) handleSendTCPData(msg *shared.Message) {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		c.logger.Error("Failed to unmarshal TCP data", zap.Error(err))
		return
	}

	// Don't parse into individual TLS records - capture the raw TCP chunk
	rawTCPData := make([]byte, len(tcpData.Data))
	copy(rawTCPData, tcpData.Data)
	c.capturedTrafficMu.Lock()
	c.capturedTraffic = append(c.capturedTraffic, rawTCPData)
	count := len(c.capturedTraffic)
	c.capturedTrafficMu.Unlock()
	c.logger.Info("Captured outgoing raw TCP chunk", zap.Int("bytes", len(rawTCPData)))
	c.logger.Info("Total captured chunks now", zap.Int("count", count))

	// Forward TLS data from TEE_K to website via our TCP connection
	conn := c.tcpConn

	if conn == nil {
		c.logger.Error("No TCP connection to website available")
		return
	}

	// Forward TLS data to website
	_, err := conn.Write(tcpData.Data)
	if err != nil {
		c.logger.Error("Failed to forward TLS data to website", zap.Error(err))
		return
	}
}

// tcpToWebsocket reads from TCP connection and processes data
func (c *Client) tcpToWebsocket() {
	nActive := activeResponseCaptures.Add(1)
	defer activeResponseCaptures.Add(-1)
	if nActive > 1 {
		c.logger.Warn("Overlapping response-capture loop", zap.Int64("concurrent_captures", nActive))
	}
	defer func() {
		if c.isClosing.Load() && c.tcpConn != nil {
			c.tcpConn.Close()
		}
	}()

	buffer := make([]byte, TCPBufferSize)
	var pending []byte // Buffer for incomplete TLS packets
	// Post-response idle flush: after at least one complete response record,
	// treat 5 consecutive 1s read timeouts between records as end-of-response.
	// Before the first response record, the core protocol timeout owns the wait.
	const idleFlushAfter = 5
	idleStreak := 0
	var requestSentObserved bool

	// Handshake-stall guard: before the HTTP request is sent we're still
	// relaying the TLS handshake. A proxy tunnel can stay open but silent when
	// the target is unreachable, so the loop would otherwise spin forever. Abort
	// after this many consecutive 1s read timeouts with no handshake byte.
	const handshakeStallAfter = 15
	handshakeIdleStreak := 0

	for {
		if c.isClosing.Load() {
			break
		}

		if c.tcpConn != nil {
			c.tcpConn.SetReadDeadline(time.Now().Add(DefaultTCPReadTimeout))
		}

		// Reset idle clock first time we observe request-sent.
		if !requestSentObserved && c.httpRequestSent.Load() {
			requestSentObserved = true
			idleStreak = 0
		}

		n, err := c.tcpConn.Read(buffer)

		// Process any received data before handling EOF
		eofReceived := false
		if err != nil {
			if err == io.EOF {
				c.logger.Info("TCP connection closed by server (EOF)")
				eofReceived = true // Mark EOF but continue to process any final data
			} else {
				if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
					// Only treat idle as "done" after capturing at least one
					// complete response record and while cleanly between records.
					// Pre-response silence remains bounded by the core protocol
					// timeout instead of being mistaken for a completed response.
					if c.httpRequestSent.Load() && len(c.batchedResponses) > 0 && pending == nil {
						idleStreak++
						if idleStreak >= idleFlushAfter {
							c.logger.Info("Server idle after response — flushing to TEE_T",
								zap.Duration("idle_for", time.Duration(idleStreak)*DefaultTCPReadTimeout))
							eofReceived = true
						} else {
							continue
						}
					} else if !c.httpRequestSent.Load() {
						// Handshake phase: bound the wait so a silent proxy tunnel
						// (target unreachable) fails fast instead of hanging.
						handshakeIdleStreak++
						if handshakeIdleStreak >= handshakeStallAfter {
							c.terminateConnectionWithError(
								"target server unresponsive during TLS handshake",
								fmt.Errorf("no handshake data after %ds (proxy tunnel idle)", handshakeStallAfter))
							return
						}
						continue
					} else {
						// Request sent, but no complete response exists yet or a record
						// is incomplete: keep waiting.
						continue
					}
				} else if !isClientNetworkShutdownError(err) {
					c.logger.Error("TCP read error", zap.Error(err))

					break
				} else {
					break
				}
			}
		} else if n > 0 {
			// Any byte from the server resets the idle clocks.
			idleStreak = 0
			handshakeIdleStreak = 0
		}

		// If we got data (n > 0), process it even if EOF was also received
		if n > 0 {
			// Append new data to any pending data
			data := append(pending, buffer[:n]...)
			pending = nil
			offset := 0

			// Process complete TLS packets
			for offset < len(data) {
				// Need at least 5 bytes for TLS record header
				if offset+5 > len(data) {
					pending = data[offset:]
					break
				}

				// Get packet length from TLS header
				length := int(data[offset+3])<<8 | int(data[offset+4])
				fullLength := length + 5

				// Check if we have the complete packet
				if offset+fullLength > len(data) {
					pending = data[offset:]
					break
				}

				// Extract the complete TLS packet
				packet := make([]byte, fullLength)
				copy(packet, data[offset:offset+fullLength])
				c.capturedTrafficMu.Lock()
				c.capturedTraffic = append(c.capturedTraffic, packet)
				c.capturedTrafficMu.Unlock()

				c.logger.Info("Captured incoming raw TCP chunk", zap.Int("bytes", len(packet)))

				// Log TLS record details for debugging
				recordType := packet[0]
				recordVersion := uint16(packet[1])<<8 | uint16(packet[2])
				recordTypeStr := "unknown"
				switch recordType {
				case 20:
					recordTypeStr = "ChangeCipherSpec"
				case 21:
					recordTypeStr = "Alert"
				case 22:
					recordTypeStr = "Handshake"
				case 23:
					recordTypeStr = "ApplicationData"
				}

				c.logger.Debug("Captured complete TLS record",
					zap.Int("total_bytes", len(packet)),
					zap.Int("payload_bytes", length),
					zap.Uint8("record_type", recordType),
					zap.String("record_type_name", recordTypeStr),
					zap.Uint16("tls_version", recordVersion))

				if !c.handshakeComplete.Load() {
					// During handshake: Forward to TEE_K
					env := &teeproto.Envelope{
						TimestampMs: time.Now().UnixMilli(),
						Payload: &teeproto.Envelope_TcpData{
							TcpData: &teeproto.TCPData{Data: packet},
						},
					}

					if err := c.sendEnvelope(env); err != nil {
						if !isClientNetworkShutdownError(err) {
							c.logger.Error("Failed to send TCP data to TEE_K", zap.Error(err))
						}
						break
					}
				} else {
					// After handshake: Process for split AEAD
					c.processTLSRecordFromData(packet)
				}

				offset += fullLength
			}
		} // Close the "if n > 0" block

		// After processing any final data, break if EOF was received
		if eofReceived {
			// A real EOF before any response record leaves downstream with
			// nothing to verify, so terminate immediately.
			if len(c.batchedResponses) == 0 {
				err := fmt.Errorf("target server returned no response data")
				c.logger.Error("No response captured before EOF — aborting session", zap.Error(err))
				c.terminateConnectionWithError("Target server returned no response data", err)
				return
			}
			c.logger.Info("Sending responses to TEE_T")
			if err := c.sendBatchedResponses(); err != nil {
				c.terminateConnectionWithError("Failed to send batched responses", err)
				return
			}
			break
		}
	}
}

// Helper function to detect network errors that occur during normal shutdown
func isClientNetworkShutdownError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}
