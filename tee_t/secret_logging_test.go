package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestRequestReconstructionPayloadIsAbsentFromDebugLogs(t *testing.T) {
	redacted := []byte("tee-t-redacted-sentinel")
	stream := []byte("tee-t-stream-sentinel!!")

	var logs bytes.Buffer
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&logs), zapcore.DebugLevel)
	teet := &TEET{logger: &shared.Logger{Logger: zap.New(core)}}
	if _, err := teet.reconstructFullRequestWithStreams(
		redacted,
		[]shared.RequestRedactionRange{{Start: 0, Length: len(stream)}},
		[][]byte{stream},
	); err != nil {
		t.Fatal(err)
	}

	for _, forbidden := range [][]byte{redacted, stream} {
		if strings.Contains(logs.String(), string(forbidden)) ||
			strings.Contains(logs.String(), base64.StdEncoding.EncodeToString(forbidden)) {
			t.Fatalf("request reconstruction payload appeared in debug logs: %s", logs.String())
		}
	}
}

func TestRequestReconstructionDoesNotLogPayloads(t *testing.T) {
	source, err := os.ReadFile("crypto_handlers.go")
	if err != nil {
		t.Fatal(err)
	}

	for _, forbidden := range []string{
		`zap.Binary("redacted_preview"`,
		`zap.Binary("stream_preview"`,
		`zap.Binary("reconstructed_preview"`,
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("request reconstruction payload is passed to logging: %s", forbidden)
		}
	}
}
