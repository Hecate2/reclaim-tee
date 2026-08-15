package mpc

import (
	"bytes"
	"testing"
)

func TestGarbledReleaseWipesScratchAndPayload(t *testing.T) {
	owner := &engine{}
	scratch := &garbleScratch{
		wires:  []wire{{l0: Label{D0: 1}, l1: Label{D1: 2}}},
		tables: []Label{{D0: 3, D1: 4}},
		random: []byte{5, 6, 7},
	}
	tableAlias := scratch.tables
	inputAlias := []Label{{D0: 8, D1: 9}}
	payload := &OnlinePayload{
		Key:                [16]byte{1},
		Tables:             tableAlias,
		GarblerInputs:      inputAlias,
		OutputTranslations: [OutputBits / 8]byte{1},
		garbled:            &garbled{wires: scratch.wires, tables: scratch.tables, scratch: scratch, owner: owner},
	}

	payload.Release()
	payload.Release()

	if scratch.wires[0] != (wire{}) || tableAlias[0] != (Label{}) || !allZeroBytes(scratch.random) {
		t.Fatal("garbling scratch retained secret material after release")
	}
	if inputAlias[0] != (Label{}) || payload.Key != ([16]byte{}) || payload.OutputTranslations != ([OutputBits / 8]byte{}) {
		t.Fatal("online payload retained secret material after release")
	}
	if payload.Tables != nil || payload.GarblerInputs != nil || payload.garbled != nil {
		t.Fatal("online payload retained released references")
	}
}

func TestGarbleRNGFailureWipesScratchBeforePoolPut(t *testing.T) {
	e := &engine{numWires: 2 * InputBits}
	scratch := &garbleScratch{
		wires:  make([]wire, e.numWires),
		tables: []Label{{D0: 1}},
		random: make([]byte, 16+(2*InputBits)*16),
	}
	scratch.wires[0] = wire{l0: Label{D0: 2}, l1: Label{D1: 3}}
	for i := range scratch.random {
		scratch.random[i] = 4
	}
	e.pool.New = func() any { return scratch }
	e.pool.Put(scratch)

	if _, err := e.garble(bytes.NewReader(nil), new([16]byte)); err == nil {
		t.Fatal("garble succeeded with empty randomness source")
	}
	got := e.pool.Get().(*garbleScratch)
	if got != scratch {
		t.Fatal("sync.Pool did not return the tested scratch object")
	}
	if got.wires[0] != (wire{}) || got.tables[0] != (Label{}) || !allZeroBytes(got.random) {
		t.Fatal("failed garble returned secret material to pool")
	}
}

func TestProtocolSessionDestroyIsIdempotent(t *testing.T) {
	garbler := &GarblerSession{
		evaluatorWires: []wire{{l0: Label{D0: 1}}},
		otPads:         []SenderOT{{R0: Label{D0: 2}, R1: Label{D1: 3}}},
		outputWires:    []wire{{l1: Label{D0: 4}}},
	}
	garbler.Destroy()
	garbler.Destroy()
	if garbler.evaluatorWires != nil || garbler.otPads != nil || garbler.outputWires != nil || !garbler.corrected || !garbler.verified {
		t.Fatal("garbler session was not terminally cleared")
	}
	if _, err := ApplyCorrections(garbler, make([]bool, InputBits)); err == nil {
		t.Fatal("destroyed garbler session remained usable")
	}

	payload := &OnlinePayload{Key: [16]byte{5}, GarblerInputs: []Label{{D0: 6}}}
	evaluator := &EvaluatorSession{payload: payload, ots: []ReceiverOT{{R: Label{D0: 7}}}}
	evaluator.inputBits[0] = true
	evaluator.Destroy()
	evaluator.Destroy()
	if evaluator.payload != nil || evaluator.ots != nil || evaluator.inputBits[0] || !evaluator.evaluated {
		t.Fatal("evaluator session was not terminally cleared")
	}
	if payload.Key != ([16]byte{}) || payload.GarblerInputs != nil {
		t.Fatal("evaluator destroy did not release its payload")
	}
	if _, err := EvaluatorOnline(evaluator, make([]OTMask, InputBits)); err == nil {
		t.Fatal("destroyed evaluator session remained usable")
	}
}

func TestBaseOTDestroyMakesStateUnusable(t *testing.T) {
	sender := &BaseOTSenderState{session: [32]byte{1}, seeds: [BaseOTCount]BaseOTSeedPair{{Zero: Label{D0: 2}}}}
	sender.Destroy()
	sender.Destroy()
	if sender.session != ([32]byte{}) || sender.seeds[0] != (BaseOTSeedPair{}) {
		t.Fatal("base OT sender state retained secret material")
	}
	if _, _, err := FinishBaseOTSender(sender, nil); err == nil {
		t.Fatal("destroyed base OT sender state remained usable")
	}

	receiver := &BaseOTReceiverState{session: [32]byte{1}, delta: Label{D0: 2}}
	receiver.Destroy()
	receiver.Destroy()
	if receiver.session != ([32]byte{}) || receiver.delta != (Label{}) {
		t.Fatal("base OT receiver state retained secret material")
	}
	if _, _, err := FinishBaseOTReceiver(receiver, nil); err == nil {
		t.Fatal("destroyed base OT receiver state remained usable")
	}
}

func TestExtensionDestroyMakesStateUnusable(t *testing.T) {
	receiver := &ExtensionReceiverState{
		commitment: ExtensionCommitment{U: []byte{1}}, choices: []byte{2}, tMatrix: []byte{3},
	}
	receiver.Destroy()
	receiver.Destroy()
	if receiver.commitment.U != nil || receiver.commitment.SessionID != ([32]byte{}) || receiver.commitment.Count != 0 || receiver.choices != nil || receiver.tMatrix != nil {
		t.Fatal("extension receiver state retained secret material")
	}
	if _, err := FinishExtensionReceiver(receiver, nil); err == nil {
		t.Fatal("destroyed extension receiver state remained usable")
	}

	sender := &ExtensionSenderState{
		commitment: ExtensionCommitment{U: []byte{1}}, delta: Label{D0: 2}, rows: []Label{{D0: 3}},
	}
	sender.Destroy()
	sender.Destroy()
	if sender.commitment.U != nil || sender.commitment.SessionID != ([32]byte{}) || sender.commitment.Count != 0 || sender.delta != (Label{}) || sender.rows != nil {
		t.Fatal("extension sender state retained secret material")
	}
	if _, err := FinishExtensionSender(sender, nil); err == nil {
		t.Fatal("destroyed extension sender state remained usable")
	}
}

func allZeroBytes(in []byte) bool {
	for _, value := range in {
		if value != 0 {
			return false
		}
	}
	return true
}
