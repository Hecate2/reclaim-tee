package providers

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeResponseBodyMapsDecodedBoundariesToRawBytes(t *testing.T) {
	tests := []struct {
		name         string
		raw          []byte
		charset      string
		decodedMatch string
		wantRaw      []byte
	}{
		{
			name:         "ISO-8859-1",
			raw:          []byte{'S', 'e', 0xf1, 'o', 'r'},
			charset:      "ISO-8859-1",
			decodedMatch: "Señor",
			wantRaw:      []byte{'S', 'e', 0xf1, 'o', 'r'},
		},
		{
			name:         "Shift_JIS",
			raw:          []byte{0x82, 0xa0, 'x'},
			charset:      "shift_jis",
			decodedMatch: "あ",
			wantRaw:      []byte{0x82, 0xa0},
		},
		{
			name:         "UTF-16LE",
			raw:          []byte{0xff, 0xfe, 'x', 0, 0xe9, 0, 'y', 0},
			charset:      "utf-16le",
			decodedMatch: "é",
			wantRaw:      []byte{0xe9, 0},
		},
		{
			name:         "valid UTF-8 identity",
			raw:          []byte("Señor"),
			charset:      "UTF-8",
			decodedMatch: "Señor",
			wantRaw:      []byte("Señor"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := decodeResponseBody(test.raw, test.charset)
			if err != nil {
				t.Fatalf("decodeResponseBody() error = %v", err)
			}
			decodedStart := strings.Index(body.text, test.decodedMatch)
			if decodedStart < 0 {
				t.Fatalf("decoded body %q does not contain %q", body.text, test.decodedMatch)
			}
			rawStart, rawEnd, err := body.rawRange(decodedStart, decodedStart+len(test.decodedMatch))
			if err != nil {
				t.Fatalf("rawRange() error = %v", err)
			}
			if got := test.raw[rawStart:rawEnd]; !bytes.Equal(got, test.wantRaw) {
				t.Fatalf("mapped raw range = %x, want %x", got, test.wantRaw)
			}
		})
	}
}
