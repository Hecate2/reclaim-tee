package client

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func debugJSONLogger(output *bytes.Buffer) *shared.Logger {
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(output), zapcore.DebugLevel)
	return &shared.Logger{Logger: zap.New(core)}
}

func TestRequestPayloadIsAbsentFromDebugLogs(t *testing.T) {
	const secret = "client-log-secret-sentinel"
	request := []byte("GET /?token=" + secret + " HTTP/1.1\r\nHost: example.com\r\n\r\n")
	start := bytes.Index(request, []byte(secret))

	var logs bytes.Buffer
	client := NewClient("")
	client.logger = debugJSONLogger(&logs)
	client.requestRedactionRanges = []shared.RequestRedactionRange{{
		Start:  start,
		Length: len(secret),
		Type:   shared.RedactionTypeSensitive,
	}}

	if _, _, err := client.createRedactedRequest(request); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatalf("request secret appeared in debug logs: %s", logs.String())
	}
}

func TestProtocolSecretsAreNotLogged(t *testing.T) {
	for file, forbidden := range map[string][]string{
		"redaction_build.go": {
			`zap.String("request"`,
			`zap.String("line"`,
		},
		"client.go": {
			`zap.String("data", string(dataToProcess))`,
			`zap.String("parameters"`,
		},
		"oprf.go": {
			`zap.String("output"`,
			`zap.String("data", string(oprfData.Data))`,
			`zap.String("params"`,
		},
		"verification.go": {
			`zap.String("preview", string(parsed.ActualContent`,
			`zap.String("hex", fmt.Sprintf("%x", parsed.ActualContent`,
			`zap.String("preview", responseStr`,
		},
		"verification_bundle.go": {
			`zap.String("data", string(originalData))`,
			`zap.String("original", originalData)`,
			`zap.String("oprf_encoded", finalOPRF)`,
		},
	} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, pattern := range forbidden {
			if strings.Contains(string(source), pattern) {
				t.Fatalf("%s passes protocol secret to logging: %s", file, pattern)
			}
		}
	}
}
