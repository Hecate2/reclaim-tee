package main

import (
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestHandleBatchedEncryptedResponsesRejectsSecondBatch(t *testing.T) {
	const sessionID = "single-response-batch"
	manager := NewTEETSessionManager()
	manager.SetLogger(shared.NewNopLogger())
	if err := manager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register session: %v", err)
	}
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	session.ConnMutex.Lock()
	session.TEEKConn = newReceiverTestWebSocket(t)
	session.ConnMutex.Unlock()

	state := &TEETSessionState{session: session}
	manager.SetTEETSessionState(sessionID, state)
	teet := &TEET{sessionManager: manager, logger: shared.NewNopLogger()}
	identity := &teetSessionIdentity{session: session}

	first := &shared.Message{
		SessionID: sessionID,
		Data: shared.BatchedEncryptedResponseData{
			Responses: []shared.EncryptedResponseData{
				{EncryptedData: []byte{1}, Tag: []byte{2}, SeqNum: 0},
				{EncryptedData: []byte{3}, Tag: []byte{4}, SeqNum: 1},
			},
			SessionID:  sessionID,
			TotalCount: 2,
		},
	}
	if err := teet.handleBatchedEncryptedResponses(identity, first); err != nil {
		t.Fatalf("handle first multi-record batch: %v", err)
	}
	if got := len(session.ResponseState.PendingEncryptedResponses); got != 2 {
		t.Fatalf("pending responses after first batch = %d, want 2", got)
	}
	if got := len(session.TranscriptData); got != 2 {
		t.Fatalf("transcript records after first batch = %d, want 2", got)
	}

	second := &shared.Message{
		SessionID: sessionID,
		Data: shared.BatchedEncryptedResponseData{
			Responses: []shared.EncryptedResponseData{
				{EncryptedData: []byte{5}, Tag: []byte{6}, SeqNum: 2},
			},
			SessionID:  sessionID,
			TotalCount: 1,
		},
	}
	err = teet.handleBatchedEncryptedResponses(identity, second)
	if err == nil || !strings.Contains(err.Error(), "multiple encrypted response batches") {
		t.Fatalf("handle second batch error = %v, want multiple-batch rejection", err)
	}
	if got := len(session.ResponseState.PendingEncryptedResponses); got != 2 {
		t.Fatalf("second batch changed pending responses: got %d, want 2", got)
	}
	if got := len(session.TranscriptData); got != 2 {
		t.Fatalf("second batch changed transcript records: got %d, want 2", got)
	}
}
