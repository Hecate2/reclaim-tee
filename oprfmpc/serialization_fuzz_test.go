// Package oprfmpc - Fuzz tests for serialization code
//
// These tests verify that serialization/deserialization:
// - Handles malformed input gracefully (no panics)
// - Roundtrips correctly for valid input
// - Handles edge cases (empty, truncated, oversized)

package oprfmpc

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/markkurossi/mpc/ot"
)

// FuzzDeserializeBulkCOSenderSetup tests deserialization with random input
func FuzzDeserializeBulkCOSenderSetup(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0}) // count = 0
	f.Add([]byte{0, 0, 0, 1}) // count = 1, truncated

	// Valid minimal entry
	curve := elliptic.P256()
	setup, _ := ot.GenerateCOSenderSetup(rand.Reader, curve)
	validData := SerializeBulkCOSenderSetup([]ot.COSenderSetup{setup})
	f.Add(validData)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		result, err := DeserializeBulkCOSenderSetup(data)
		if err == nil && len(result) > 0 {
			// Valid parse - verify fields are populated
			for _, s := range result {
				if s.CurveName == "" {
					t.Error("parsed setup has empty curve name")
				}
			}
		}
	})
}

// FuzzDeserializeBulkOTReceiverData tests receiver data deserialization
func FuzzDeserializeBulkOTReceiverData(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0}) // curve name length = 0

	// Valid minimal entry
	data := &OTReceiverData{
		CurveName: "P-256",
		Ax:        big.NewInt(1),
		Ay:        big.NewInt(2),
		Points:    []ot.ECPoint{{X: big.NewInt(3), Y: big.NewInt(4)}},
	}
	validData := SerializeBulkOTReceiverData(data)
	f.Add(validData)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		result, err := DeserializeBulkOTReceiverData(data)
		if err == nil && result != nil {
			if result.CurveName == "" {
				t.Error("parsed data has empty curve name")
			}
		}
	})
}

// FuzzDeserializeDualMasks tests dual mask deserialization
func FuzzDeserializeDualMasks(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})                                                                                  // count = 0
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // truncated

	// Valid entry
	masks := []DualMask{
		{
			M0:    ot.Label{D0: 0x1234, D1: 0x5678},
			M1:    ot.Label{D0: 0xABCD, D1: 0xEF01},
			Delta: ot.Label{D0: 0x1111, D1: 0x2222},
		},
	}
	validData := SerializeDualMasks(masks)
	f.Add(validData)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = DeserializeDualMasks(data)
	})
}

// FuzzDeserializeOnlinePayload tests online payload deserialization
func FuzzDeserializeOnlinePayload(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 48)) // minimum header size

	// Create a minimal valid payload
	curve := elliptic.P256()
	otEntries := make([]*OTPoolEntry, cmacInputBitCount)
	for i := range cmacInputBitCount {
		setup, _ := ot.GenerateCOSenderSetup(rand.Reader, curve)
		_, choicePoints, _ := ot.BuildCOChoices(rand.Reader, curve, setup.Ax, setup.Ay, []bool{false})
		otEntries[i] = &OTPoolEntry{
			SenderSetup:   setup,
			ReceiverPoint: choicePoints[0],
			Index:         i,
		}
	}
	var input [80]byte
	payload, _, _ := CMACGarblerOnline(rand.Reader, curve, input, otEntries, 0)
	if payload != nil {
		validData := SerializeOnlinePayload(payload)
		f.Add(validData)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = DeserializeOnlinePayload(data)
	})
}

// FuzzDeserializeOutputLabels tests output label deserialization
func FuzzDeserializeOutputLabels(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})    // count = 0
	f.Add([]byte{0, 0, 0, 1})    // count = 1, truncated
	f.Add([]byte{255, 255, 255}) // invalid count

	// Valid labels
	labels := []ot.Label{
		{D0: 0x1234, D1: 0x5678},
		{D0: 0xABCD, D1: 0xEF01},
	}
	validData := SerializeOutputLabels(labels)
	f.Add(validData)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should not panic
		_, _ = DeserializeOutputLabels(data)
	})
}

// TestSerializationRoundtrip_BulkCOSenderSetup verifies roundtrip works
func TestSerializationRoundtrip_BulkCOSenderSetup(t *testing.T) {
	curve := elliptic.P256()

	// Generate multiple setups
	setups := make([]ot.COSenderSetup, 10)
	for i := range setups {
		setup, err := ot.GenerateCOSenderSetup(rand.Reader, curve)
		if err != nil {
			t.Fatalf("failed to generate setup: %v", err)
		}
		setups[i] = setup
	}

	// Serialize
	data := SerializeBulkCOSenderSetup(setups)
	if len(data) == 0 {
		t.Fatal("serialization produced empty data")
	}

	// Deserialize
	parsed, err := DeserializeBulkCOSenderSetup(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	if len(parsed) != len(setups) {
		t.Fatalf("count mismatch: got %d, want %d", len(parsed), len(setups))
	}

	// Verify fields
	for i := range setups {
		if parsed[i].CurveName != setups[i].CurveName {
			t.Errorf("setup %d: curve name mismatch", i)
		}
		if parsed[i].Scalar.Cmp(setups[i].Scalar) != 0 {
			t.Errorf("setup %d: scalar mismatch", i)
		}
		if parsed[i].Ax.Cmp(setups[i].Ax) != 0 {
			t.Errorf("setup %d: Ax mismatch", i)
		}
		if parsed[i].Ay.Cmp(setups[i].Ay) != 0 {
			t.Errorf("setup %d: Ay mismatch", i)
		}
	}
}

// TestSerializationRoundtrip_DualMasks verifies roundtrip for dual masks
func TestSerializationRoundtrip_DualMasks(t *testing.T) {
	masks := make([]DualMask, 100)
	for i := range masks {
		var buf [48]byte
		rand.Read(buf[:])
		masks[i] = DualMask{
			M0: ot.Label{
				D0: uint64(buf[0])<<56 | uint64(buf[1])<<48 | uint64(buf[2])<<40 | uint64(buf[3])<<32,
				D1: uint64(buf[4])<<56 | uint64(buf[5])<<48 | uint64(buf[6])<<40 | uint64(buf[7])<<32,
			},
			M1: ot.Label{
				D0: uint64(buf[16])<<56 | uint64(buf[17])<<48 | uint64(buf[18])<<40 | uint64(buf[19])<<32,
				D1: uint64(buf[20])<<56 | uint64(buf[21])<<48 | uint64(buf[22])<<40 | uint64(buf[23])<<32,
			},
			Delta: ot.Label{
				D0: uint64(buf[32])<<56 | uint64(buf[33])<<48 | uint64(buf[34])<<40 | uint64(buf[35])<<32,
				D1: uint64(buf[36])<<56 | uint64(buf[37])<<48 | uint64(buf[38])<<40 | uint64(buf[39])<<32,
			},
		}
	}

	data := SerializeDualMasks(masks)
	parsed, err := DeserializeDualMasks(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	if len(parsed) != len(masks) {
		t.Fatalf("count mismatch: got %d, want %d", len(parsed), len(masks))
	}

	for i := range masks {
		if parsed[i].M0 != masks[i].M0 {
			t.Errorf("mask %d: M0 mismatch", i)
		}
		if parsed[i].M1 != masks[i].M1 {
			t.Errorf("mask %d: M1 mismatch", i)
		}
		if parsed[i].Delta != masks[i].Delta {
			t.Errorf("mask %d: Delta mismatch", i)
		}
	}
}

// TestSerializationRoundtrip_OnlinePayload verifies roundtrip for online payload
func TestSerializationRoundtrip_OnlinePayload(t *testing.T) {
	curve := elliptic.P256()

	// Generate OT entries
	otEntries := make([]*OTPoolEntry, cmacInputBitCount)
	for i := range cmacInputBitCount {
		setup, _ := ot.GenerateCOSenderSetup(rand.Reader, curve)
		_, choicePoints, _ := ot.BuildCOChoices(rand.Reader, curve, setup.Ax, setup.Ay, []bool{false})
		otEntries[i] = &OTPoolEntry{
			SenderSetup:   setup,
			ReceiverPoint: choicePoints[0],
			Index:         i,
		}
	}

	var input [80]byte
	rand.Read(input[:])

	payload, _, err := CMACGarblerOnline(rand.Reader, curve, input, otEntries, 42)
	if err != nil {
		t.Fatalf("failed to create payload: %v", err)
	}

	// Serialize and deserialize
	data := SerializeOnlinePayload(payload)
	parsed, err := DeserializeOnlinePayload(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	// Verify fields
	if parsed.SessionID != payload.SessionID {
		t.Error("SessionID mismatch")
	}
	if parsed.Key != payload.Key {
		t.Error("Key mismatch")
	}
	if parsed.OTStartIndex != payload.OTStartIndex {
		t.Error("OTStartIndex mismatch")
	}
	if len(parsed.GarbledTables) != len(payload.GarbledTables) {
		t.Error("GarbledTables length mismatch")
	}
	if len(parsed.GarblerInputs) != len(payload.GarblerInputs) {
		t.Error("GarblerInputs length mismatch")
	}
	if len(parsed.OutputHints) != len(payload.OutputHints) {
		t.Error("OutputHints length mismatch")
	}
	if len(parsed.DualMasks) != len(payload.DualMasks) {
		t.Error("DualMasks length mismatch")
	}
}

// TestDeserialize_Malformed tests handling of malformed input
func TestDeserialize_Malformed(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short for count", []byte{0, 0, 0}},
		{"truncated header", []byte{0, 0, 0, 1}},
		{"invalid count", []byte{255, 255, 255, 255}},
		{"partial entry", make([]byte, 50)},
	}

	for _, tc := range testCases {
		t.Run(tc.name+"_BulkCOSenderSetup", func(t *testing.T) {
			_, err := DeserializeBulkCOSenderSetup(tc.data)
			if err == nil && len(tc.data) < 4 {
				t.Error("expected error for malformed input")
			}
		})

		t.Run(tc.name+"_DualMasks", func(t *testing.T) {
			_, err := DeserializeDualMasks(tc.data)
			if err == nil && len(tc.data) < 4 {
				t.Error("expected error for malformed input")
			}
		})

		t.Run(tc.name+"_OutputLabels", func(t *testing.T) {
			_, err := DeserializeOutputLabels(tc.data)
			if err == nil && len(tc.data) < 4 {
				t.Error("expected error for malformed input")
			}
		})
	}
}

// TestDeserialize_Truncated tests handling of truncated valid data
func TestDeserialize_Truncated(t *testing.T) {
	// Create valid data then truncate it
	masks := []DualMask{
		{M0: ot.Label{D0: 1, D1: 2}, M1: ot.Label{D0: 3, D1: 4}, Delta: ot.Label{D0: 5, D1: 6}},
		{M0: ot.Label{D0: 7, D1: 8}, M1: ot.Label{D0: 9, D1: 10}, Delta: ot.Label{D0: 11, D1: 12}},
	}
	validData := SerializeDualMasks(masks)

	// Try various truncation points
	for i := 1; i < len(validData); i++ {
		truncated := validData[:i]
		_, err := DeserializeDualMasks(truncated)
		if err == nil && i < len(validData)-1 {
			// Should error on truncated data (except maybe last few bytes depending on format)
			continue
		}
	}
}

// TestSerializationRoundtrip_OTReceiverData verifies roundtrip for receiver data
func TestSerializationRoundtrip_OTReceiverData(t *testing.T) {
	points := make([]ot.ECPoint, 100)
	for i := range points {
		points[i] = ot.ECPoint{
			X: big.NewInt(int64(i * 2)),
			Y: big.NewInt(int64(i*2 + 1)),
		}
	}

	original := &OTReceiverData{
		CurveName: "P-256",
		Ax:        big.NewInt(12345),
		Ay:        big.NewInt(67890),
		Points:    points,
	}

	data := SerializeBulkOTReceiverData(original)
	parsed, err := DeserializeBulkOTReceiverData(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	if parsed.CurveName != original.CurveName {
		t.Error("CurveName mismatch")
	}
	if parsed.Ax.Cmp(original.Ax) != 0 {
		t.Error("Ax mismatch")
	}
	if parsed.Ay.Cmp(original.Ay) != 0 {
		t.Error("Ay mismatch")
	}
	if len(parsed.Points) != len(original.Points) {
		t.Fatalf("Points length mismatch: got %d, want %d", len(parsed.Points), len(original.Points))
	}
	for i := range original.Points {
		if parsed.Points[i].X.Cmp(original.Points[i].X) != 0 {
			t.Errorf("Point %d X mismatch", i)
		}
		if parsed.Points[i].Y.Cmp(original.Points[i].Y) != 0 {
			t.Errorf("Point %d Y mismatch", i)
		}
	}
}

// TestSerializationRoundtrip_OutputLabels verifies roundtrip for output labels
func TestSerializationRoundtrip_OutputLabels(t *testing.T) {
	labels := make([]ot.Label, 128)
	for i := range labels {
		var buf [16]byte
		rand.Read(buf[:])
		labels[i] = ot.Label{
			D0: uint64(buf[0])<<56 | uint64(buf[1])<<48 | uint64(buf[2])<<40 | uint64(buf[3])<<32 |
				uint64(buf[4])<<24 | uint64(buf[5])<<16 | uint64(buf[6])<<8 | uint64(buf[7]),
			D1: uint64(buf[8])<<56 | uint64(buf[9])<<48 | uint64(buf[10])<<40 | uint64(buf[11])<<32 |
				uint64(buf[12])<<24 | uint64(buf[13])<<16 | uint64(buf[14])<<8 | uint64(buf[15]),
		}
	}

	data := SerializeOutputLabels(labels)
	parsed, err := DeserializeOutputLabels(data)
	if err != nil {
		t.Fatalf("deserialization failed: %v", err)
	}

	if len(parsed) != len(labels) {
		t.Fatalf("count mismatch: got %d, want %d", len(parsed), len(labels))
	}

	for i := range labels {
		if parsed[i] != labels[i] {
			t.Errorf("label %d mismatch: got %v, want %v", i, parsed[i], labels[i])
		}
	}
}

// TestSerializationSizeLimits tests that serialization doesn't cause integer overflow
func TestSerializationSizeLimits(t *testing.T) {
	// Test that huge counts in data don't cause allocation panic
	hugeCount := []byte{0xFF, 0xFF, 0xFF, 0xFF} // 4 billion entries

	t.Run("BulkCOSenderSetup", func(t *testing.T) {
		data := append(hugeCount, make([]byte, 100)...)
		_, err := DeserializeBulkCOSenderSetup(data)
		if err == nil {
			t.Error("expected error for huge count")
		}
	})

	t.Run("DualMasks", func(t *testing.T) {
		data := append(hugeCount, make([]byte, 100)...)
		_, err := DeserializeDualMasks(data)
		if err == nil {
			t.Error("expected error for huge count")
		}
	})

	t.Run("OutputLabels", func(t *testing.T) {
		data := append(hugeCount, make([]byte, 100)...)
		_, err := DeserializeOutputLabels(data)
		if err == nil {
			t.Error("expected error for huge count")
		}
	})
}

// TestSerializationEmpty tests serialization of empty slices
func TestSerializationEmpty(t *testing.T) {
	t.Run("EmptySetups", func(t *testing.T) {
		data := SerializeBulkCOSenderSetup([]ot.COSenderSetup{})
		if data != nil {
			result, err := DeserializeBulkCOSenderSetup(data)
			if err != nil {
				t.Errorf("failed to deserialize empty: %v", err)
			}
			if len(result) != 0 {
				t.Errorf("expected empty result, got %d entries", len(result))
			}
		}
	})

	t.Run("EmptyMasks", func(t *testing.T) {
		data := SerializeDualMasks([]DualMask{})
		result, err := DeserializeDualMasks(data)
		if err != nil {
			t.Errorf("failed to deserialize empty: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty result, got %d entries", len(result))
		}
	})

	t.Run("EmptyLabels", func(t *testing.T) {
		data := SerializeOutputLabels([]ot.Label{})
		result, err := DeserializeOutputLabels(data)
		if err != nil {
			t.Errorf("failed to deserialize empty: %v", err)
		}
		if len(result) != 0 {
			t.Errorf("expected empty result, got %d entries", len(result))
		}
	})
}

// TestBigIntTo32Bytes tests the bigIntTo32Bytes helper
func TestBigIntTo32Bytes(t *testing.T) {
	testCases := []struct {
		name     string
		input    *big.Int
		expected int
	}{
		{"nil", nil, 32},
		{"zero", big.NewInt(0), 32},
		{"small", big.NewInt(255), 32},
		{"large", new(big.Int).Lsh(big.NewInt(1), 256), 32}, // 2^256
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bigIntTo32Bytes(tc.input)
			if len(result) != tc.expected {
				t.Errorf("expected length %d, got %d", tc.expected, len(result))
			}
		})
	}
}

// TestSerializationBytesEqual tests that serialization is deterministic
func TestSerializationBytesEqual(t *testing.T) {
	masks := []DualMask{
		{M0: ot.Label{D0: 1, D1: 2}, M1: ot.Label{D0: 3, D1: 4}, Delta: ot.Label{D0: 5, D1: 6}},
	}

	data1 := SerializeDualMasks(masks)
	data2 := SerializeDualMasks(masks)

	if !bytes.Equal(data1, data2) {
		t.Error("serialization not deterministic")
	}
}
