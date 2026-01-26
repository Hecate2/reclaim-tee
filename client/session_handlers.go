package client

import (
	"fmt"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// handleSessionReady processes session ready messages from TEE_K
func (c *Client) handleSessionReady(msg *shared.Message) {
	var sessionData shared.SessionReadyData
	if err := msg.UnmarshalData(&sessionData); err != nil {
		c.logger.Error("Failed to unmarshal session ready data", zap.Error(err))
		return
	}

	// Store session ID and check for pending requests
	c.sessionMutex.Lock()
	c.sessionID = sessionData.SessionID
	pending := c.connectionRequestPending
	hasPendingRequest := c.pendingConnectionRequest != nil
	c.sessionMutex.Unlock()

	c.logger.Info("Received session ID", zap.String("session_id", c.sessionID))

	// Send pending connection request if we have one
	if pending && hasPendingRequest {
		if err := c.sendPendingConnectionRequest(); err != nil {
			c.logger.Error("Failed to send pending connection request", zap.Error(err))
			c.terminateConnectionWithError("Failed to send pending connection request", err)
			return
		}
	}
}

// handleError handles error messages from TEE_K (fail-fast implementation)
func (c *Client) handleError(msg *shared.Message) {
	var errorData shared.ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		c.terminateConnectionWithError("Failed to unmarshal error data from TEE_K", err)
		return
	}

	// Any error from TEE_K should terminate the session immediately
	c.terminateConnectionWithError("Received error from TEE_K", fmt.Errorf("TEE_K error: %s", errorData.Message))
}

// handleTEETError handles error messages from TEE_T (fail-fast implementation)
func (c *Client) handleTEETError(msg *shared.Message) {
	var errorData shared.ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		c.terminateConnectionWithError("Failed to unmarshal TEE_T error", err)
		return
	}

	// Any error from TEE_T should terminate the session immediately
	c.terminateConnectionWithError("Received error from TEE_T", fmt.Errorf("TEE_T error: %s", errorData.Message))
}
