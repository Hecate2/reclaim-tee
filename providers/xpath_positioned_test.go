package providers

import (
	"strings"
	"testing"
)

func TestExtractHTMLElementsIndexesIncludesParserError(t *testing.T) {
	_, err := ExtractHTMLElementsIndexes("\x1f\x8b", `//span`, false)
	if err == nil {
		t.Fatal("Expected binary input error")
	}

	for _, expected := range []string{
		`failed to find XPath: "//span"`,
		"binary input is not supported",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error %q to contain %q", err, expected)
		}
	}
}
