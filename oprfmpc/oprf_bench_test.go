package oprfmpc

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

// setupOTEntries builds one batch of matched garbler+receiver OT entries
// (cmacInputBitCount = 640) outside the timed loop.
func setupOTEntries(b interface{ Fatalf(string, ...any) }, curve elliptic.Curve, indexOffset int) ([]*OTPoolEntry, []*OTReceiverEntry) {
	otEntries := make([]*OTPoolEntry, cmacInputBitCount)
	rxEntries := make([]*OTReceiverEntry, cmacInputBitCount)
	for i := range cmacInputBitCount {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			b.Fatalf("setup gen failed at %d: %v", i, err)
		}
		bundle, choicePoints, err := ot.BuildCOChoices(rand.Reader, curve, setup.Ax, setup.Ay, []bool{i%2 == 0})
		if err != nil {
			b.Fatalf("BuildCOChoices failed at %d: %v", i, err)
		}
		otEntries[i] = &OTPoolEntry{
			SenderSetup:   setup,
			ReceiverPoint: choicePoints[0],
			Index:         indexOffset + i,
		}
		rxEntries[i] = &OTReceiverEntry{
			ReceiverBundle:    bundle,
			SenderPublicPoint: ot.ECPoint{X: setup.Ax, Y: setup.Ay},
			Index:             indexOffset + i,
		}
	}
	return otEntries, rxEntries
}

// BenchmarkOPRF_Garbler: per-call garbler-side cost — circuit garble +
// 640 P-256 ScalarMults for random-OT pad derivation. Work TEE_K does per OPRF.
// Calls Release in the same iteration to model the prod flow
// (CMACGarblerOnline → serialize → release), so the pool reuses scratch.
func BenchmarkOPRF_Garbler(b *testing.B) {
	curve := elliptic.P256()
	otEntries, _ := setupOTEntries(b, curve, 0)
	var garblerInput [80]byte
	rand.Read(garblerInput[:])

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		payload, _, err := CMACGarblerOnline(rand.Reader, curve, garblerInput, otEntries, 0)
		if err != nil {
			b.Fatalf("garbler failed: %v", err)
		}
		payload.Release()
	}
}

// BenchmarkOPRF_Evaluator: per-call evaluator-side cost — 640 P-256
// ScalarMults + garbled-circuit eval. Work TEE_T does per OPRF.
func BenchmarkOPRF_Evaluator(b *testing.B) {
	curve := elliptic.P256()
	otEntries, rxEntries := setupOTEntries(b, curve, 0)
	var garblerInput, evaluatorInput [80]byte
	rand.Read(garblerInput[:])
	rand.Read(evaluatorInput[:])

	payload, garblerSession, err := CMACGarblerOnline(rand.Reader, curve, garblerInput, otEntries, 0)
	if err != nil {
		b.Fatalf("setup garble failed: %v", err)
	}
	_, corrections, err := CMACEvaluatorPrepare(payload, evaluatorInput, rxEntries)
	if err != nil {
		b.Fatalf("setup prepare failed: %v", err)
	}
	masks, err := CMACGarblerApplyCorrections(garblerSession, corrections)
	if err != nil {
		b.Fatalf("setup corrections failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		evaluatorSession, _, err := CMACEvaluatorPrepare(payload, evaluatorInput, rxEntries)
		if err != nil {
			b.Fatalf("prepare failed: %v", err)
		}
		_, err = CMACEvaluatorOnline(curve, evaluatorSession, masks)
		if err != nil {
			b.Fatalf("evaluator failed: %v", err)
		}
	}
}

// BenchmarkOPRF_EndToEnd: garble + evaluate + verify, single-threaded,
// no network. Headline number for "OPRFs/sec per core in-process."
// Models prod by releasing the garble scratch after the evaluator has
// read GarbledTables (so subsequent iterations reuse the slab).
func BenchmarkOPRF_EndToEnd(b *testing.B) {
	curve := elliptic.P256()
	otEntries, rxEntries := setupOTEntries(b, curve, 0)
	var garblerInput, evaluatorInput [80]byte
	rand.Read(garblerInput[:])
	rand.Read(evaluatorInput[:])

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		payload, session, err := CMACGarblerOnline(rand.Reader, curve, garblerInput, otEntries, 0)
		if err != nil {
			b.Fatalf("garbler: %v", err)
		}
		evaluatorSession, corrections, err := CMACEvaluatorPrepare(payload, evaluatorInput, rxEntries)
		if err != nil {
			b.Fatalf("prepare: %v", err)
		}
		masks, err := CMACGarblerApplyCorrections(session, corrections)
		if err != nil {
			b.Fatalf("corrections: %v", err)
		}
		result, err := CMACEvaluatorOnline(curve, evaluatorSession, masks)
		if err != nil {
			b.Fatalf("evaluator: %v", err)
		}
		payload.Release()
		if _, err := CMACGarblerVerifyOutput(session, result.OutputLabels); err != nil {
			b.Fatalf("verify: %v", err)
		}
	}
}

// BenchmarkOPRF_Garble_only: just circ.Garble, with Release on every
// iteration so the slab is reused. Isolates the cost of garble itself
// once the per-circuit scratch pool is hot.
func BenchmarkOPRF_Garble_only(b *testing.B) {
	circ := aesCMACCircuit
	var key [32]byte
	rand.Read(key[:])

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		g, err := circ.Garble(rand.Reader, key[:])
		if err != nil {
			b.Fatalf("garble: %v", err)
		}
		g.Release()
	}
}

// BenchmarkOPRF_Serialize: encode one online payload to the wire format.
func BenchmarkOPRF_Serialize(b *testing.B) {
	curve := elliptic.P256()
	otEntries, _ := setupOTEntries(b, curve, 0)
	var garblerInput [80]byte
	rand.Read(garblerInput[:])
	payload, _, err := CMACGarblerOnline(rand.Reader, curve, garblerInput, otEntries, 0)
	if err != nil {
		b.Fatalf("garbler: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = SerializeOnlinePayload(payload)
	}
}
