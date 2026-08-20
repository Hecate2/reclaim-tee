package main

import (
	"errors"
	"testing"
)

func TestMarshalRecoveredPanic(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value any
	}{
		{name: "string", value: "panic text"},
		{name: "error", value: errors.New("panic text")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := marshalRecoveredPanic(tt.value)
			if err != nil {
				t.Fatalf("marshal recovered panic: %v", err)
			}
			if want := `"panic text"`; string(got) != want {
				t.Fatalf("payload = %s, want %s", got, want)
			}
		})
	}
}
