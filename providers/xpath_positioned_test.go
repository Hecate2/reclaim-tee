package providers

import (
	"strings"
	"testing"
)

func TestExtractHTMLElementsIndexesIncludesParserError(t *testing.T) {
	_, err := ExtractHTMLElementsIndexes(`<div><span></div>`, `//span`, false)
	if err == nil {
		t.Fatal("Expected malformed HTML error")
	}

	for _, expected := range []string{
		`failed to find XPath: "//span"`,
		"HTML parsing failed",
		"expected closing tag </span>",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Errorf("Expected error %q to contain %q", err, expected)
		}
	}
}
