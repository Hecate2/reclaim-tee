package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestOTPrecomputeBeginCountPreflightBeforeStateOrBaseOT(t *testing.T) {
	epoch := mpc.ExtensionEpoch([32]byte{5})
	makeRequest := func(t *testing.T, count int) *teeproto.OTPrecomputeRequest {
		t.Helper()
		begin := mpc.PrecomputeBegin{SessionID: [32]byte{8}, Count: uint32(count), Epoch: epoch}
		payload, err := mpc.MarshalPrecomputeBegin(begin)
		if err != nil {
			t.Fatal(err)
		}
		return &teeproto.OTPrecomputeRequest{Count: uint32(count), IsInitial: true, Epoch: epoch, OtSenderSetup: payload}
	}

	teet := &TEET{logger: shared.NewNopLogger()}
	leaseCalled := false
	err := teet.handleOTPrecomputeBegin(nil, 1, func(func() error) error {
		leaseCalled = true
		return nil
	}, makeRequest(t, mpc.MaxPrecomputeOTs+1))
	if err == nil || !strings.Contains(err.Error(), "unsupported OT precompute count") {
		t.Fatalf("max+1 error=%v, want count rejection", err)
	}
	if leaseCalled || teet.otReceiverState != nil {
		t.Fatal("rejected count entered state lease or created receiver state")
	}

	stop := errors.New("stop after accepted-count preflight")
	err = teet.handleOTPrecomputeBegin(nil, 1, func(func() error) error {
		leaseCalled = true
		return stop
	}, makeRequest(t, mpc.MaxPrecomputeOTs))
	if !errors.Is(err, stop) {
		t.Fatalf("maximum accepted count error=%v, want lease sentinel", err)
	}
	if !leaseCalled || teet.otReceiverState != nil {
		t.Fatal("maximum accepted count did not reach lease or mutated receiver state")
	}
}
