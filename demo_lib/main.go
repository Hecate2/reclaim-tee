package main

// #cgo CFLAGS: -I.
// #cgo LDFLAGS: -L../bin -lreclaim
/*
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

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

// Go types for CGO - use LibGoSlice to avoid conflict with CGO-generated GoSlice
typedef struct { void *data; ptrdiff_t len; ptrdiff_t cap; } LibGoSlice;

// Callback function type for lazy loading ZK circuits
typedef void (*zk_init_callback_t)(unsigned char algorithm_id);

// Function declarations
reclaim_error_t reclaim_execute_protocol(char* request_json, char* config_json, char** claim_json, int* claim_length);
void reclaim_free_string(char* str);
char* reclaim_get_error_message(reclaim_error_t error);
char* reclaim_get_version(void);
uint8_t InitAlgorithm(uint8_t algorithmID, LibGoSlice provingKey, LibGoSlice r1cs);
void Free(void* pointer);
void SetZKInitCallback(zk_init_callback_t callback);
void MarkZKInitComplete(unsigned char algorithmID, bool success);
bool IsAlgorithmInitialized(unsigned char algorithmID);

// New extraction functions
typedef struct { void *p; ptrdiff_t n; } ExtractResult;
ExtractResult ExtractHTMLElementsIndexes(LibGoSlice params);
ExtractResult ExtractJSONValueIndexes(LibGoSlice params);

// Forward declaration for our callback
extern void goZKInitCallback(unsigned char algorithm_id);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"unsafe"
)

// Algorithm IDs from gnark library
const (
	CHACHA20_OPRF = 3
	AES_128_OPRF  = 4
	AES_256_OPRF  = 5
)

// circuitConfig holds the configuration for a ZK circuit
type circuitConfig struct {
	algorithmID   uint8
	pkFile        string
	r1csFile      string
	algorithmName string
}

// circuitsRegistry maps algorithm IDs to their circuit configurations
var circuitsRegistry = map[uint8]circuitConfig{
	CHACHA20_OPRF: {
		algorithmID:   CHACHA20_OPRF,
		pkFile:        "pk.chacha20_oprf",
		r1csFile:      "r1cs.chacha20_oprf",
		algorithmName: "CHACHA20_OPRF",
	},
	AES_128_OPRF: {
		algorithmID:   AES_128_OPRF,
		pkFile:        "pk.aes128_oprf",
		r1csFile:      "r1cs.aes128_oprf",
		algorithmName: "AES_128_OPRF",
	},
	AES_256_OPRF: {
		algorithmID:   AES_256_OPRF,
		pkFile:        "pk.aes256_oprf",
		r1csFile:      "r1cs.aes256_oprf",
		algorithmName: "AES_256_OPRF",
	},
}

// circuitsPath holds the resolved circuits directory path
var circuitsPath string

// resolveCircuitsPath finds the circuits directory
func resolveCircuitsPath() (string, error) {
	possiblePaths := []string{
		"circuits",
		"../circuits",
		"../../circuits",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("circuits directory not found in any of the expected locations")
}

//export goZKInitCallback
func goZKInitCallback(algorithmID C.uchar) {
	config, ok := circuitsRegistry[uint8(algorithmID)]
	if !ok {
		fmt.Printf("Unknown algorithm ID for lazy loading: %d\n", algorithmID)
		C.MarkZKInitComplete(algorithmID, C.bool(false))
		return
	}

	fmt.Printf("Lazy loading ZK circuit: %s (ID: %d)\n", config.algorithmName, algorithmID)

	// Resolve circuits path if not already done
	if circuitsPath == "" {
		var err error
		circuitsPath, err = resolveCircuitsPath()
		if err != nil {
			fmt.Printf("Failed to resolve circuits directory: %v\n", err)
			C.MarkZKInitComplete(algorithmID, C.bool(false))
			return
		}
	}

	// Read proving key
	pkPath := filepath.Join(circuitsPath, config.pkFile)
	pkData, err := os.ReadFile(pkPath)
	if err != nil {
		fmt.Printf("Failed to read proving key %s: %v\n", pkPath, err)
		C.MarkZKInitComplete(algorithmID, C.bool(false))
		return
	}

	// Read R1CS
	r1csPath := filepath.Join(circuitsPath, config.r1csFile)
	r1csData, err := os.ReadFile(r1csPath)
	if err != nil {
		fmt.Printf("Failed to read R1CS %s: %v\n", r1csPath, err)
		C.MarkZKInitComplete(algorithmID, C.bool(false))
		return
	}

	// Create LibGoSlice structures for CGO
	pkSlice := C.LibGoSlice{
		data: unsafe.Pointer(&pkData[0]),
		len:  C.ptrdiff_t(len(pkData)),
		cap:  C.ptrdiff_t(len(pkData)),
	}

	r1csSlice := C.LibGoSlice{
		data: unsafe.Pointer(&r1csData[0]),
		len:  C.ptrdiff_t(len(r1csData)),
		cap:  C.ptrdiff_t(len(r1csData)),
	}

	// Call InitAlgorithm through the shared library
	success := C.InitAlgorithm(C.uint8_t(algorithmID), pkSlice, r1csSlice)
	if success == 0 {
		fmt.Printf("Failed to initialize %s circuit\n", config.algorithmName)
		C.MarkZKInitComplete(algorithmID, C.bool(false))
		return
	}

	fmt.Printf("Successfully lazy loaded ZK circuit: %s (ID: %d, PK: %d bytes, R1CS: %d bytes)\n",
		config.algorithmName, algorithmID, len(pkData), len(r1csData))

	C.MarkZKInitComplete(algorithmID, C.bool(true))
}

// setupZKLazyLoading sets up the lazy loading callback for ZK circuits
func setupZKLazyLoading() error {
	// Resolve and validate circuits directory exists
	var err error
	circuitsPath, err = resolveCircuitsPath()
	if err != nil {
		return err
	}

	fmt.Printf("Setting up ZK lazy loading (circuits dir: %s)\n", circuitsPath)

	// Set the lazy loading callback
	C.SetZKInitCallback(C.zk_init_callback_t(C.goZKInitCallback))

	fmt.Println("ZK lazy loading configured - circuits will be loaded on demand")
	return nil
}

func main() {
	fmt.Println("=== Sample Application using libreclaim Shared Library ===")

	// Setup lazy loading for ZK circuits (loaded on demand when needed)
	if err := setupZKLazyLoading(); err != nil {
		log.Printf("Warning: Failed to setup ZK lazy loading: %v", err)
		log.Println("Continuing without ZK circuit lazy loading...")
	}

	// Create the provider data with optional context
	providerData := map[string]interface{}{
		"name": "http",
		"params": map[string]interface{}{
			"url":    "https://example.com/",
			"method": "GET",
			"responseMatches": []map[string]interface{}{
				{
					"value": "{{addr}}",
					"type":  "contains",
				},
			},
			"responseRedactions": []map[string]interface{}{
				{
					"xPath": "/html/body/div/p[2]/a",
					"regex": "href=\"https://(?<addr>iana.org)/.*?\"",
					"hash":  "oprf-mpc",
				},
			},
			"paramValues": map[string]string{
				"addr": "iana.org",
			},
		},
		"secretParams": map[string]interface{}{
			"headers": map[string]interface{}{
				"accept": "application/json, text/plain, */*",
			},
		},
		// Optional context that will be included in the claim (JSON string)
		"context": "{\"purpose\":\"demo\",\"version\":\"1.0\"}",
	}

	// routerUrl is required — the library hits /allocate to resolve the
	// TEE pair and JWT. attestorUrl is optional.
	configData := map[string]interface{}{
		//"routerUrl":   "https://tee.reclaimprotocol.org",
		"attestorUrl": "ws://localhost:8001/ws",
	}

	providerJSON, err := json.Marshal(providerData)
	if err != nil {
		log.Fatalf("Failed to marshal provider JSON: %v", err)
	}

	configJSON, err := json.Marshal(configData)
	if err != nil {
		log.Fatalf("Failed to marshal config JSON: %v", err)
	}

	// fmt.Printf("URL: %s\n", providerData["params"].(map[string]interface{})["url"])
	fmt.Printf("Config: %v\n", configData)

	cProviderJSON := C.CString(string(providerJSON))
	defer C.reclaim_free_string(cProviderJSON)

	cConfigJSON := C.CString(string(configJSON))
	defer C.reclaim_free_string(cConfigJSON)

	fmt.Printf("Starting protocol...\n")

	var claimJSON *C.char
	var claimLength C.int
	result := C.reclaim_execute_protocol(cProviderJSON, cConfigJSON, &claimJSON, &claimLength)
	if result != C.RECLAIM_SUCCESS {
		errorMsg := C.reclaim_get_error_message(result)
		log.Fatalf("Failed to execute protocol: %s", C.GoString(errorMsg))
	}
	defer C.reclaim_free_string(claimJSON)

	claimDataStr := C.GoStringN(claimJSON, claimLength)
	var claimData map[string]interface{}
	if err := json.Unmarshal([]byte(claimDataStr), &claimData); err != nil {
		log.Fatalf("Failed to parse claim JSON: %v", err)
	}

	// Print full JSON for debugging/integration
	fmt.Println("\nFull Claim JSON:")
	prettyJSON, err := json.MarshalIndent(claimData, "", "  ")
	if err != nil {
		fmt.Printf("Error formatting JSON: %v\n", err)
		fmt.Println(claimDataStr)
	} else {
		fmt.Println(string(prettyJSON))
	}

	fmt.Println("Sample application completed successfully!")

}
