package mpc

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	extensionCommitmentHeaderSize = 4 + 32 + 8 + 4 + 4 + 32 + 32
	extensionChallengeHeaderSize  = 4 + 32 + 32 + 32 + 4
	extensionProofSize            = 4 + 32 + 32 + 16 + BaseOTCount*16
)

// MarshalExtensionCommitment encodes the fixed IKNP matrix and transcript.
func MarshalExtensionCommitment(commitment *ExtensionCommitment) ([]byte, error) {
	if commitment == nil {
		return nil, errors.New("mpc: nil OT extension commitment")
	}
	padded, err := extensionPaddedCount(int(commitment.Count))
	if err != nil {
		return nil, err
	}
	if int(commitment.PaddedCount) != padded {
		return nil, fmt.Errorf("mpc: padded OT count %d, want %d", commitment.PaddedCount, padded)
	}
	wantU := BaseOTCount * padded / 8
	if len(commitment.U) != wantU {
		return nil, fmt.Errorf("mpc: OT extension matrix length %d, want %d", len(commitment.U), wantU)
	}
	out := make([]byte, extensionCommitmentHeaderSize+len(commitment.U))
	copy(out[:4], "KOC2")
	copy(out[4:36], commitment.SessionID[:])
	binary.BigEndian.PutUint64(out[36:44], commitment.StartIndex)
	binary.BigEndian.PutUint32(out[44:48], commitment.Count)
	binary.BigEndian.PutUint32(out[48:52], commitment.PaddedCount)
	copy(out[52:84], commitment.EpochHash[:])
	copy(out[84:116], commitment.Transcript[:])
	copy(out[116:], commitment.U)
	return out, nil
}

// UnmarshalExtensionCommitment decodes and bounds-checks the exact KOC2 frame.
func UnmarshalExtensionCommitment(data []byte) (*ExtensionCommitment, error) {
	if len(data) < extensionCommitmentHeaderSize {
		return nil, errors.New("mpc: OT extension commitment is too short")
	}
	if string(data[:4]) != "KOC2" {
		return nil, errors.New("mpc: unsupported OT extension commitment version")
	}
	count := int(binary.BigEndian.Uint32(data[44:48]))
	padded, err := extensionPaddedCount(count)
	if err != nil {
		return nil, err
	}
	encodedPadded := int(binary.BigEndian.Uint32(data[48:52]))
	if encodedPadded != padded {
		return nil, fmt.Errorf("mpc: padded OT count %d, want %d", encodedPadded, padded)
	}
	wantLen := uint64(extensionCommitmentHeaderSize) + uint64(BaseOTCount)*uint64(padded)/8
	if uint64(len(data)) != wantLen {
		return nil, fmt.Errorf("mpc: OT extension commitment length %d, want %d", len(data), wantLen)
	}
	commitment := &ExtensionCommitment{
		StartIndex: uint64(binary.BigEndian.Uint64(data[36:44])), Count: uint32(count),
		PaddedCount: uint32(padded), U: append([]byte(nil), data[116:]...),
	}
	copy(commitment.SessionID[:], data[4:36])
	copy(commitment.EpochHash[:], data[52:84])
	copy(commitment.Transcript[:], data[84:116])
	return commitment, nil
}

// MarshalExtensionChallenge encodes every independently sampled chi value.
func MarshalExtensionChallenge(challenge *ExtensionChallenge) ([]byte, error) {
	if challenge == nil || len(challenge.Chi) == 0 {
		return nil, errors.New("mpc: invalid OT extension challenge")
	}
	wantTranscript := extensionChallengeTranscript(challenge)
	if challenge.Transcript != wantTranscript {
		return nil, errors.New("mpc: OT extension challenge hash mismatch")
	}
	out := make([]byte, extensionChallengeHeaderSize+len(challenge.Chi)*16)
	copy(out[:4], "KCH2")
	copy(out[4:36], challenge.SessionID[:])
	copy(out[36:68], challenge.Commitment[:])
	copy(out[68:100], challenge.Transcript[:])
	binary.BigEndian.PutUint32(out[100:104], uint32(len(challenge.Chi)))
	for i, coefficient := range challenge.Chi {
		coefficient.put(out[104+i*16 : 104+(i+1)*16])
	}
	return out, nil
}

// UnmarshalExtensionChallenge rejects alternate versions, truncation, and
// trailing bytes before reconstructing the full coefficient vector.
func UnmarshalExtensionChallenge(data []byte) (*ExtensionChallenge, error) {
	if len(data) < extensionChallengeHeaderSize || string(data[:4]) != "KCH2" {
		return nil, errors.New("mpc: invalid OT extension challenge")
	}
	count := int(binary.BigEndian.Uint32(data[100:104]))
	maxPadded, err := extensionPaddedCount(maxExtensionOTs)
	if err != nil {
		return nil, err
	}
	if count <= 0 || count > extensionChallengeCount(maxPadded) {
		return nil, fmt.Errorf("mpc: invalid OT extension challenge count %d", count)
	}
	wantLen := uint64(extensionChallengeHeaderSize) + uint64(count)*16
	if uint64(len(data)) != wantLen {
		return nil, fmt.Errorf("mpc: OT extension challenge length %d, want %d", len(data), wantLen)
	}
	challenge := &ExtensionChallenge{Chi: make([]Label, count)}
	copy(challenge.SessionID[:], data[4:36])
	copy(challenge.Commitment[:], data[36:68])
	copy(challenge.Transcript[:], data[68:100])
	for i := range challenge.Chi {
		challenge.Chi[i] = labelFromBytes(data[104+i*16 : 104+(i+1)*16])
	}
	wantTranscript := extensionChallengeTranscript(challenge)
	if challenge.Transcript != wantTranscript {
		return nil, errors.New("mpc: OT extension challenge hash mismatch")
	}
	return challenge, nil
}

// MarshalExtensionProof encodes x followed by all 128 t_i values.
func MarshalExtensionProof(proof *ExtensionProof) ([]byte, error) {
	if proof == nil {
		return nil, errors.New("mpc: nil OT extension proof")
	}
	out := make([]byte, extensionProofSize)
	copy(out[:4], "KPR2")
	copy(out[4:36], proof.SessionID[:])
	copy(out[36:68], proof.Transcript[:])
	proof.X.put(out[68:84])
	for i, check := range proof.T {
		check.put(out[84+i*16 : 84+(i+1)*16])
	}
	return out, nil
}

// UnmarshalExtensionProof decodes the fixed-size x,t_0,...,t_127 proof.
func UnmarshalExtensionProof(data []byte) (*ExtensionProof, error) {
	if len(data) != extensionProofSize || string(data[:4]) != "KPR2" {
		return nil, errors.New("mpc: invalid OT extension proof")
	}
	proof := &ExtensionProof{X: labelFromBytes(data[68:84])}
	copy(proof.SessionID[:], data[4:36])
	copy(proof.Transcript[:], data[36:68])
	for i := range proof.T {
		proof.T[i] = labelFromBytes(data[84+i*16 : 84+(i+1)*16])
	}
	return proof, nil
}
