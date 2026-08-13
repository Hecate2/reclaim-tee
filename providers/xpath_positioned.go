package providers

import (
	"fmt"

	xp "github.com/reclaimprotocol/xpath-go"
	"go.uber.org/zap"
)

// extractHTMLElementsIndexes evaluates an XPath against the provided HTML string
// and returns absolute byte ranges for each matched element. When contentsOnly
// ExtractHTMLElementsIndexes extracts the byte positions of HTML elements matching an XPath expression
// is true, the range covers only the element's inner content if available.
func ExtractHTMLElementsIndexes(html string, xpathExpression string, contentsOnly bool) ([]IndexRange, error) {
	logger.Info("Starting extractHTMLElementsIndexes", zap.String("component", "XPath"), zap.String("operation", "extractHTMLElementsIndexes"), zap.String("xpath", xpathExpression), zap.Int("html_size", len(html)), zap.Bool("contents_only", contentsOnly))

	processedHTML := html
	logger.Debug("Executing XPath query with options", zap.String("component", "XPath"), zap.String("operation", "extractHTMLElementsIndexes"))

	matches, err := xp.QueryWithOptions(xpathExpression, processedHTML, xp.Options{
		IncludeLocation: true,
		OutputFormat:    "nodes",
		ContentsOnly:    contentsOnly,
	})
	if err != nil {
		logger.Error("XPath query failed", zap.String("component", "XPath"), zap.String("operation", "extractHTMLElementsIndexes"), zap.Error(err))
		return nil, fmt.Errorf("Failed to find XPath: \"%s\"", xpathExpression)
	}
	if len(matches) == 0 {
		logger.Warn("XPath returned no matches", zap.String("component", "XPath"), zap.String("operation", "extractHTMLElementsIndexes"))
		return nil, fmt.Errorf("failed to find XPath: \"%s\"", xpathExpression)
	}

	logger.Debug("XPath found matches", zap.String("component", "XPath"), zap.String("operation", "extractHTMLElementsIndexes"), zap.Int("match_count", len(matches)))

	out := make([]IndexRange, 0, len(matches))
	for i, m := range matches {
		logger.Debug("Match found", zap.String("component", "XPath"), zap.String("operation", "extractHTMLElementsIndexes"), zap.String("level", "verbose"), zap.Int("match_index", i+1), zap.Int("start", m.StartLocation), zap.Int("end", m.EndLocation), zap.String("content", html[m.StartLocation:m.EndLocation]))
		out = append(out, IndexRange{Start: m.StartLocation, End: m.EndLocation})
	}

	logger.Info("XPath extraction complete", zap.String("component", "XPath"), zap.String("operation", "extractHTMLElementsIndexes"), zap.Int("ranges_found", len(out)))
	return out, nil
}
