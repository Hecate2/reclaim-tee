package client

import (
	"bytes"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
)

// makeRecords builds n well-formed TLS 1.3 app-data records (outer type 0x17)
// whose payload is filled with `fill`. EncryptedData (payload minus the 16-byte
// tag) therefore begins with `fill`, so a record's origin is identifiable.
func makeRecords(fill byte, n, payloadLen int) [][]byte {
	recs := make([][]byte, n)
	for i := range recs {
		hdr := []byte{0x17, 0x03, 0x03, byte(payloadLen >> 8), byte(payloadLen)}
		recs[i] = append(hdr, bytes.Repeat([]byte{fill}, payloadLen)...)
	}
	return recs
}

func newCaptureClient() *Client {
	c := NewClient("")
	c.teetConn = &websocket.Conn{} // non-nil; processTLSRecord only nil-checks it
	return c
}

// assertPure verifies a client batched exactly its own records: right count and
// every record's first ciphertext byte equal to `fill`. A foreign byte = a
// cross-session record injected; a short count = a record dropped mid-stream.
func assertPure(t *testing.T, name string, c *Client, fill byte, want int) {
	t.Helper()
	if len(c.batchedResponses) != want {
		t.Errorf("%s: batched %d records, want %d (record dropped or injected mid-stream)", name, len(c.batchedResponses), want)
	}
	for i, r := range c.batchedResponses {
		if len(r.EncryptedData) == 0 || r.EncryptedData[0] != fill {
			t.Errorf("%s: record %d is foreign (first byte %q, want %q) — cross-session contamination", name, i, firstByte(r.EncryptedData), fill)
			return
		}
	}
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// TestRecordProcessingStateRace drives two Client capture goroutines (as happens
// when an SDK retry overlaps the previous session) through processTLSRecordFromData
// at the same time. With the package-global recordProcessingState buffer they race:
// -race flags the unsynchronized buffer access, and records cross between sessions
// (one gets a foreign record, the other drops one → tail tag failure in prod). With
// a per-Client buffer, each stays pure.
func TestRecordProcessingStateRace(t *testing.T) {
	const n, plen = 300, 100
	a := newCaptureClient()
	b := newCaptureClient()
	aRecs := makeRecords('A', n, plen)
	bRecs := makeRecords('B', n, plen)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); for _, r := range aRecs { a.processTLSRecordFromData(r) } }()
	go func() { defer wg.Done(); for _, r := range bRecs { b.processTLSRecordFromData(r) } }()
	wg.Wait()

	assertPure(t, "A", a, 'A', n)
	assertPure(t, "B", b, 'B', n)
}
