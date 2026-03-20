package client

import "github.com/reclaimprotocol/reclaim-tee/shared"

// TLSToHTTPMapping tracks the relationship between TLS and HTTP positions
type TLSToHTTPMapping struct {
	SeqNum     uint64
	HTTPPos    int    // Position within HTTP content
	TLSPos     int    // Position within TLS stream
	Length     int    // Length of HTTP data inside this TLS packet
	Ciphertext []byte // Original ciphertext for this segment
}

// TLSAnalysisResult contains the results of analyzing TLS records
type TLSAnalysisResult struct {
	ProtocolRedactions []shared.ResponseRedactionRange // Session tickets, alerts, etc.
	HTTPMappings       []TLSToHTTPMapping              // HTTP content mappings
	AllHTTPContent     []byte                          // Concatenated HTTP content
	TotalTLSOffset     int                             // Final offset in TLS stream after all records
}

// OPRFMPCRangeMapping tracks the relationship between HTTP and TLS positions
// for OPRF MPC ranges, enabling matching of OPRF outputs back to HTTP data
type OPRFMPCRangeMapping struct {
	HTTPStart  int // Position within HTTP response
	HTTPLength int // Length of the range
	TLSStart   int // Position within TLS stream (sent to TEEs)
	TLSLength  int // Length in TLS stream
}
