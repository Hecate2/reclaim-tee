package main

import (
	"strings"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestHandleOPRFOnlineFullRejectsTwentyOneBeforeStateOrOT(t *testing.T) {
	const sessionID = "oprf-range-limit"
	manager := NewTEETSessionManager()
	if err := manager.RegisterSession(sessionID); err != nil {
		t.Fatalf("register session: %v", err)
	}
	session, err := manager.GetSession(sessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	state := &TEETSessionState{session: session}
	manager.SetTEETSessionState(sessionID, state)
	teet := &TEET{sessionManager: manager, logger: shared.NewNopLogger()}
	otConsumeReached := false
	identity := &teetSessionIdentity{
		session: session,
		beforeOTReceiverConsume: func() {
			otConsumeReached = true
		},
	}

	err = teet.handleOPRFOnlineFull(identity, &teeproto.OPRFOnlineFull{
		SessionId:   sessionID,
		TotalRanges: int32(shared.MaxOPRFRangesPerSession + 1),
	})
	if err == nil || !strings.Contains(err.Error(), "too many OPRF ranges") {
		t.Fatalf("handle oversized online message error = %v, want range-limit error", err)
	}
	if otConsumeReached {
		t.Fatal("oversized online message reached OT consumption")
	}
	if state.OPRFResults != nil || state.PendingOPRF != nil || state.OPRFExpectedCount != 0 || len(state.TLSSessionHash) != 0 {
		t.Fatal("oversized online message published evaluator state")
	}
}
