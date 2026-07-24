package main

import (
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// sendEnvelopeToTEET sends a protobuf envelope directly to TEE_T with attestation check
func (t *TEEK) sendEnvelopeToTEET(sessionID string, env *teeproto.Envelope) error {
	// Ensure session ID is set
	if env.GetSessionId() == "" {
		env.SessionId = sessionID
	}

	// Use sendToTEET which includes attestation verification
	return t.sendToTEET(sessionID, env)
}

// sendBatchedEncryptedRequestToTEET sends multiple encrypted request fragments to TEE_T in a single message
func (t *TEEK) sendBatchedEncryptedRequestToTEET(sessionID string, fragments []struct {
	encryptedData   []byte
	tagSecrets      []byte
	redactionRanges []shared.RequestRedactionRange
	seqNum          uint64
}, cipherSuite uint16, baseSeqNum uint64) error {

	t.logger.WithSession(sessionID).Debug("Sending batched encrypted request to TEE_T",
		zap.Int("fragment_count", len(fragments)),
		zap.Uint64("base_seq_num", baseSeqNum))

	// Build protobuf fragments
	var pbFragments []*teeproto.EncryptedRequest
	for _, fragment := range fragments {
		// Convert redaction ranges to protobuf format
		var pbRanges []*teeproto.RequestRedactionRange
		for _, r := range fragment.redactionRanges {
			pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
				Start:  int32(r.Start),
				Length: int32(r.Length),
				Type:   r.Type,
			})
		}

		pbFragments = append(pbFragments, &teeproto.EncryptedRequest{
			EncryptedData:   fragment.encryptedData,
			TagSecrets:      fragment.tagSecrets,
			RedactionRanges: pbRanges,
			SeqNum:          fragment.seqNum,
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedEncryptedRequest{
			BatchedEncryptedRequest: &teeproto.BatchedEncryptedRequest{
				Fragments:   pbFragments,
				BaseSeqNum:  baseSeqNum,
				CipherSuite: uint32(cipherSuite),
			},
		},
	}
	return t.sendEnvelopeToTEET(sessionID, env)
}
