package main

// #cgo CFLAGS: -I.
/*
#include <stddef.h>
#include <stdlib.h>

// Opaque handle for protocol session
typedef struct reclaim_protocol* reclaim_protocol_t;

// Error codes
typedef enum {
    RECLAIM_SUCCESS = 0,
    RECLAIM_ERROR_INVALID_ARGS = -1,
    RECLAIM_ERROR_CONNECTION_FAILED = -2,
    RECLAIM_ERROR_PROTOCOL_FAILED = -3,
    RECLAIM_ERROR_TIMEOUT = -4,
    RECLAIM_ERROR_MEMORY = -5,
    RECLAIM_ERROR_SESSION_NOT_FOUND = -6,
    RECLAIM_ERROR_ALREADY_COMPLETED = -7
} reclaim_error_t;
*/
import "C"
import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	"tee-mpc/client"
	"tee-mpc/providers"
	"tee-mpc/shared"

	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/oprf"
	"go.uber.org/zap"
)

// Logger instance for the shared library
var logger *shared.Logger

// ClaimData represents the JSON structure for claim data returned from attestor
type ClaimData struct {
	Identifier string `json:"identifier"`
	Owner      string `json:"owner"`
	Provider   string `json:"provider"`
	Parameters string `json:"parameters"`
	Context    string `json:"context"`
	TimestampS uint32 `json:"timestamp_s"`
	Epoch      uint32 `json:"epoch"`
	Error      string `json:"error,omitempty"`
}

//export reclaim_execute_protocol
func reclaim_execute_protocol(request_json *C.char, config_json *C.char, claim_json **C.char, claim_length *C.int) (retErr C.reclaim_error_t) {
	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			if logger != nil {
				logger.Error("Panic recovered in reclaim_execute_protocol",
					zap.Any("panic", r),
					zap.Stack("stack"))
			}
			retErr = C.RECLAIM_ERROR_PROTOCOL_FAILED
		}
	}()

	// Initialize logger if not already initialized
	if logger == nil {
		var err error
		logger, err = shared.NewLoggerFromEnv("libreclaim")
		if err != nil {
			// Fallback to basic logger
			logger, _ = shared.NewLogger(shared.LoggerConfig{
				ServiceName: "libreclaim",
				Development: true,
			})
		}
	}

	// 🔐 TEE: Starting protocol execution
	logger.Info("🔐 TEE: Starting protocol execution",
		zap.String("function", "reclaim_execute_protocol"),
		zap.String("source", "TEE-LIBRECLAIM"))

	if request_json == nil || claim_json == nil || claim_length == nil {
		logger.Error("Invalid arguments: one or more required parameters is nil",
			zap.Bool("request_json_nil", request_json == nil),
			zap.Bool("claim_json_nil", claim_json == nil),
			zap.Bool("claim_length_nil", claim_length == nil))
		return C.RECLAIM_ERROR_INVALID_ARGS
	}

	goRequestJSON := C.GoString(request_json)
	goConfigJSON := ""
	if config_json != nil {
		goConfigJSON = C.GoString(config_json)
	}

	// Use the enhanced NewReclaimClientFromJSON function
	reclaimClient, err := client.NewReclaimClientFromJSON(goRequestJSON, goConfigJSON)
	if err != nil {
		logger.Error("Failed to create reclaim client",
			zap.Error(err),
			zap.String("request_json", goRequestJSON),
			zap.String("config_json", goConfigJSON))
		return C.RECLAIM_ERROR_INVALID_ARGS
	}
	defer reclaimClient.Close()
	defer func() {
		if r := recover(); r != nil {
			// Log panic but don't propagate - we're already cleaning up
			fmt.Printf("PANIC %+v", r)
		}
	}()

	// Parse provider data to get provider name for logging
	var providerData client.ProviderRequestData
	if err := json.Unmarshal([]byte(goRequestJSON), &providerData); err != nil {
		logger.Error("Failed to parse provider params for logging",
			zap.Error(err))
		return C.RECLAIM_ERROR_INVALID_ARGS
	}

	logger.Info("Starting protocol",
		zap.String("provider", providerData.Name),
		zap.Bool("has_secret_params", providerData.SecretParams != nil),
		zap.String("context", providerData.Context))

	// Execute the complete protocol with progress reporting
	result, err := reclaimClient.ExecuteCompleteProtocol(&providerData)
	if err != nil {
		logger.Error("Complete protocol execution failed",
			zap.Error(err),
			zap.String("provider", providerData.Name))
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	// Define response types
	type Signature struct {
		AttestorAddress string `json:"attestor_address"`
		ClaimSignature  string `json:"claim_signature"`
	}

	type CompleteResponse struct {
		Claim      ClaimData   `json:"claim"`
		Signatures []Signature `json:"signatures"`
	}

	// Signature are required
	if result.Signature == nil {
		logger.Error("No signatures returned from attestor")
		return C.RECLAIM_ERROR_PROTOCOL_FAILED
	}

	logger.Info("Protocol completed with attestor submission",
		zap.String("claim_identifier", result.Claim.Identifier),
		zap.String("provider", result.Claim.Provider),
		zap.Uint32("epoch", result.Claim.Epoch),
		zap.String("attestor_address", result.Signature.AttestorAddress))

	claimData := ClaimData{
		Identifier: result.Claim.Identifier,
		Owner:      result.Claim.Owner,
		Provider:   result.Claim.Provider,
		Parameters: result.Claim.Parameters,
		Context:    result.Claim.Context,
		TimestampS: result.Claim.TimestampS,
		Epoch:      result.Claim.Epoch,
	}

	response := CompleteResponse{
		Claim: claimData,
		Signatures: []Signature{
			{
				AttestorAddress: result.Signature.AttestorAddress,
				ClaimSignature:  "0x" + hex.EncodeToString(result.Signature.ClaimSignature),
			},
		},
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		logger.Error("Failed to marshal claim response", zap.Error(err))
		return C.RECLAIM_ERROR_MEMORY
	}

	cString := C.CString(string(jsonData))
	*claim_json = cString
	*claim_length = C.int(len(jsonData))

	return C.RECLAIM_SUCCESS
}

//export reclaim_free_string
func reclaim_free_string(str *C.char) {
	// Panic recovery - for free operations we just silently ignore
	defer func() {
		if recover() != nil {
			// Silently ignore panic in free operation
			return
		}
	}()

	if str != nil {
		C.free(unsafe.Pointer(str))
	}
}

//export reclaim_get_error_message
func reclaim_get_error_message(error C.reclaim_error_t) (result *C.char) {
	// Panic recovery - return a generic error message on panic
	defer func() {
		if recover() != nil {
			result = C.CString("Internal error occurred")
		}
	}()
	var message string
	switch error {
	case C.RECLAIM_SUCCESS:
		message = "Success"
	case C.RECLAIM_ERROR_INVALID_ARGS:
		message = "Invalid arguments"
	case C.RECLAIM_ERROR_CONNECTION_FAILED:
		message = "Connection failed"
	case C.RECLAIM_ERROR_PROTOCOL_FAILED:
		message = "Protocol failed"
	case C.RECLAIM_ERROR_TIMEOUT:
		message = "Operation timed out"
	case C.RECLAIM_ERROR_MEMORY:
		message = "Memory allocation failed"
	case C.RECLAIM_ERROR_SESSION_NOT_FOUND:
		message = "Session not found"
	case C.RECLAIM_ERROR_ALREADY_COMPLETED:
		message = "Protocol already completed"
	default:
		message = "Unknown error"
	}

	return C.CString(message)
}

//export reclaim_get_version
func reclaim_get_version() (version *C.char) {
	// Panic recovery - return a fallback version on panic
	defer func() {
		if recover() != nil {
			version = C.CString("1.0.0-error")
		}
	}()

	return C.CString("1.0.0")
}

// ============================================================================
// GNARK ZK Proof Functions (integrated from libprove.go)
// ============================================================================

//export InitAlgorithm
func InitAlgorithm(algorithmID uint8, provingKey []byte, r1cs []byte) (success bool) {
	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			if logger != nil {
				logger.Error("Panic recovered in InitAlgorithm",
					zap.Any("panic", r),
					zap.Uint8("algorithm_id", algorithmID))
			}
			success = false
		}
	}()
	// Initialize logger if not already initialized
	if logger == nil {
		var err error
		logger, err = shared.NewLoggerFromEnv("libreclaim")
		if err != nil {
			// Fallback to basic logger
			logger, _ = shared.NewLogger(shared.LoggerConfig{
				ServiceName: "libreclaim",
				Development: true,
			})
		}
	}

	logger.Info("InitAlgorithm called from external",
		zap.Uint8("algorithmID", algorithmID),
		zap.Int("provingKey_len", len(provingKey)),
		zap.Int("r1cs_len", len(r1cs)))

	result := impl.InitAlgorithm(algorithmID, provingKey, r1cs)

	logger.Info("InitAlgorithm result",
		zap.Bool("success", result),
		zap.Uint8("algorithmID", algorithmID))

	return result
}

//export Free
func Free(pointer unsafe.Pointer) {
	C.free(pointer)
}

//export Prove
func Prove(params []byte) (proofRes unsafe.Pointer, resLen int) {
	defer func() {
		if err := recover(); err != nil {
			if logger != nil {
				logger.Error("Panic in Prove function",
					zap.Any("error", err))
			}
			bRes, er := json.Marshal(err)
			if er != nil {
				if logger != nil {
					logger.Error("Failed to marshal error", zap.Error(er))
				}
			} else {
				proofRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := impl.Prove(params)
	return C.CBytes(res), len(res)
}

//export GenerateOPRFRequestData
func GenerateOPRFRequestData(params []byte) (proofRes unsafe.Pointer, resLen int) {
	defer func() {
		if err := recover(); err != nil {
			if logger != nil {
				logger.Error("Panic in GenerateOPRFRequestData function",
					zap.Any("error", err))
			}
			bRes, er := json.Marshal(err)
			if er != nil {
				if logger != nil {
					logger.Error("Failed to marshal error", zap.Error(er))
				}
			} else {
				proofRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := oprf.GenerateOPRFRequestData(params)
	return C.CBytes(res), len(res)
}

//export TOPRFFinalize
func TOPRFFinalize(params []byte) (proofRes unsafe.Pointer, resLen int) {
	defer func() {
		if err := recover(); err != nil {
			if logger != nil {
				logger.Error("Panic in TOPRFFinalize function",
					zap.Any("error", err))
			}
			bRes, er := json.Marshal(err)
			if er != nil {
				if logger != nil {
					logger.Error("Failed to marshal error", zap.Error(er))
				}
			} else {
				proofRes, resLen = C.CBytes(bRes), len(bRes)
			}
		}
	}()

	res := oprf.TOPRFFinalize(params)
	return C.CBytes(res), len(res)
}

// ============================================================================
// HTML/JSON Extraction Functions
// ============================================================================

// IndexRange represents a start and end position in a document
type IndexRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

//export ExtractHTMLElementsIndexes
func ExtractHTMLElementsIndexes(params []byte) (resultPtr unsafe.Pointer, resultLen int) {
	defer func() {
		if err := recover(); err != nil {
			if logger != nil {
				logger.Error("Panic in ExtractHTMLElementsIndexes function",
					zap.Any("error", err))
			}
			// Return error as JSON
			errResp := map[string]interface{}{
				"error": fmt.Sprintf("%v", err),
			}
			bRes, _ := json.Marshal(errResp)
			resultPtr, resultLen = C.CBytes(bRes), len(bRes)
		}
	}()

	// Parse input parameters
	var input struct {
		HTML         string `json:"html"`        // Legacy: direct string (will be escaped)
		HTMLBase64   string `json:"html_base64"` // New: base64-encoded bytes (preserves exact bytes)
		XPath        string `json:"xpath"`
		ContentsOnly bool   `json:"contentsOnly"`
	}

	if err := json.Unmarshal(params, &input); err != nil {
		errResp := map[string]interface{}{
			"error": fmt.Sprintf("failed to parse input: %v", err),
		}
		bRes, _ := json.Marshal(errResp)
		return C.CBytes(bRes), len(bRes)
	}

	// Determine which HTML format to use
	var htmlBytes []byte
	if input.HTMLBase64 != "" {
		// Prefer base64-encoded HTML (preserves exact bytes)
		decoded, err := base64.StdEncoding.DecodeString(input.HTMLBase64)
		if err != nil {
			errResp := map[string]interface{}{
				"error": fmt.Sprintf("failed to decode html_base64: %v", err),
			}
			bRes, _ := json.Marshal(errResp)
			return C.CBytes(bRes), len(bRes)
		}
		htmlBytes = decoded
	} else {
		// Fallback to legacy string format
		htmlBytes = []byte(input.HTML)
	}

	// Call the internal function
	ranges, err := providers.ExtractHTMLElementsIndexes(string(htmlBytes), input.XPath, input.ContentsOnly)
	if err != nil {
		errResp := map[string]interface{}{
			"error": fmt.Sprintf("extraction failed: %v", err),
		}
		bRes, _ := json.Marshal(errResp)
		return C.CBytes(bRes), len(bRes)
	}

	// Convert to our JSON-friendly format
	var result []IndexRange
	for _, r := range ranges {
		result = append(result, IndexRange{
			Start: r.Start,
			End:   r.End,
		})
	}

	// Return success response
	response := map[string]interface{}{
		"ranges": result,
	}
	bRes, _ := json.Marshal(response)
	return C.CBytes(bRes), len(bRes)
}

//export ExtractJSONValueIndexes
func ExtractJSONValueIndexes(params []byte) (resultPtr unsafe.Pointer, resultLen int) {
	defer func() {
		if err := recover(); err != nil {
			if logger != nil {
				logger.Error("Panic in ExtractJSONValueIndexes function",
					zap.Any("error", err))
			}
			// Return error as JSON
			errResp := map[string]interface{}{
				"error": fmt.Sprintf("%v", err),
			}
			bRes, _ := json.Marshal(errResp)
			resultPtr, resultLen = C.CBytes(bRes), len(bRes)
		}
	}()

	// Parse input parameters
	var input struct {
		Document       string `json:"document"`        // Legacy: direct string (will be escaped)
		DocumentBase64 string `json:"document_base64"` // New: base64-encoded bytes (preserves exact bytes)
		JSONPath       string `json:"jsonPath"`
	}

	if err := json.Unmarshal(params, &input); err != nil {
		errResp := map[string]interface{}{
			"error": fmt.Sprintf("failed to parse input: %v", err),
		}
		bRes, _ := json.Marshal(errResp)
		return C.CBytes(bRes), len(bRes)
	}

	// Determine which document format to use
	var docBytes []byte
	if input.DocumentBase64 != "" {
		// Prefer base64-encoded document (preserves exact bytes)
		if logger != nil {
			logger.Info("📦 Using base64-encoded document",
				zap.String("component", "JSON-EXTRACTION"),
				zap.Int("base64_length", len(input.DocumentBase64)),
				zap.String("jsonPath", input.JSONPath))
		}

		decoded, err := base64.StdEncoding.DecodeString(input.DocumentBase64)
		if err != nil {
			if logger != nil {
				logger.Error("❌ Failed to decode base64",
					zap.String("component", "JSON-EXTRACTION"),
					zap.Error(err))
			}
			errResp := map[string]interface{}{
				"error": fmt.Sprintf("failed to decode document_base64: %v", err),
			}
			bRes, _ := json.Marshal(errResp)
			return C.CBytes(bRes), len(bRes)
		}
		docBytes = decoded

		if logger != nil {
			logger.Info("✅ Successfully decoded base64",
				zap.String("component", "JSON-EXTRACTION"),
				zap.Int("decoded_bytes_length", len(docBytes)),
				zap.String("preview", string(docBytes[:min(100, len(docBytes))])))
		}
	} else {
		// Fallback to legacy string format
		if logger != nil {
			logger.Info("📝 Using legacy string format",
				zap.String("component", "JSON-EXTRACTION"),
				zap.Int("document_length", len(input.Document)))
		}
		docBytes = []byte(input.Document)
	}

	// Call the internal function
	ranges, err := providers.ExtractJSONValueIndexes(docBytes, input.JSONPath)
	if err != nil {
		errResp := map[string]interface{}{
			"error": fmt.Sprintf("extraction failed: %v", err),
		}
		bRes, _ := json.Marshal(errResp)
		return C.CBytes(bRes), len(bRes)
	}

	// Convert to our JSON-friendly format
	var result []IndexRange
	for _, r := range ranges {
		result = append(result, IndexRange{
			Start: r.Start,
			End:   r.End,
		})
	}

	// Return success response
	response := map[string]interface{}{
		"ranges": result,
	}
	bRes, _ := json.Marshal(response)
	return C.CBytes(bRes), len(bRes)
}

// Helper functions

func main() {
	// Required for CGO shared library
}

func init() {
	// Set environment variable to signal Flutter logging is available
	os.Setenv("RECLAIM_FLUTTER_LOGGING", "true")

	// Initialize logger on library load with Flutter callback support
	var err error

	// Hardcoded to development mode for now
	development := true

	// Create logger with Flutter callback support
	zapLogger, err := CreateLoggerWithFlutterCallback("libreclaim", development)
	if err != nil {
		// Fallback to shared logger if Flutter logger fails
		logger, err = shared.NewLoggerFromEnv("libreclaim")
		if err != nil {
			// Final fallback
			logger, _ = shared.NewLogger(shared.LoggerConfig{
				ServiceName: "libreclaim",
				Development: development,
			})
		}
	} else {
		// Wrap zap.Logger in shared.Logger for compatibility
		logger = &shared.Logger{
			Logger: zapLogger,
		}
	}

	// Share the Flutter-enabled logger with other packages
	shareLoggerWithPackages(logger)
}

// shareLoggerWithPackages shares the Flutter-enabled logger with providers and libclient
func shareLoggerWithPackages(sharedLogger *shared.Logger) {
	// Set logger for providers package
	providers.SetSharedLogger(sharedLogger.Logger.With(
		zap.String("source", "TEE-PROVIDERS"),
	))

	// Set logger for libclient package
	client.SetSharedLogger(sharedLogger.Logger.With(
		zap.String("source", "TEE-CLIENT"),
	))
}
