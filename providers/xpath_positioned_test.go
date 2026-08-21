package providers

import (
	"strings"
	"testing"
)

func TestExtractHTMLElementsIndexesIncludesParserError(t *testing.T) {
	for _, input := range []string{
		"\x1f\x8b",
		"<p>\x01</p>",
	} {
		_, err := ExtractHTMLElementsIndexes(input, `//span`, false)
		if err == nil {
			t.Fatalf("expected binary input error for %q", input)
		}

		for _, expected := range []string{
			`failed to find XPath: "//span"`,
			"binary input is not supported",
		} {
			if !strings.Contains(err.Error(), expected) {
				t.Errorf("expected error %q to contain %q", err, expected)
			}
		}
	}
}
