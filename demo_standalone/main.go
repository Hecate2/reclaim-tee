package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/client"
	"github.com/reclaimprotocol/reclaim-tee/minitls"
	"github.com/reclaimprotocol/reclaim-tee/providers"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
	"go.uber.org/zap"
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
	impl.CHACHA20_OPRF: {
		algorithmID:   impl.CHACHA20_OPRF,
		pkFile:        "pk.chacha20_oprf",
		r1csFile:      "r1cs.chacha20_oprf",
		algorithmName: "CHACHA20_OPRF",
	},
	impl.AES_128_OPRF: {
		algorithmID:   impl.AES_128_OPRF,
		pkFile:        "pk.aes128_oprf",
		r1csFile:      "r1cs.aes128_oprf",
		algorithmName: "AES_128_OPRF",
	},
	impl.AES_256_OPRF: {
		algorithmID:   impl.AES_256_OPRF,
		pkFile:        "pk.aes256_oprf",
		r1csFile:      "r1cs.aes256_oprf",
		algorithmName: "AES_256_OPRF",
	},
}

// circuitsDir holds the resolved circuits directory path
var circuitsDir string

// resolveCircuitsDir finds the circuits directory
func resolveCircuitsDir() (string, error) {
	// Define the circuits directory
	dir := "circuits"

	// Check if circuits directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// Try alternative paths
		alternativePaths := []string{
			"../circuits",
			"./circuits",
		}

		found := false
		for _, path := range alternativePaths {
			if _, err := os.Stat(path); err == nil {
				dir = path
				found = true
				break
			}
		}

		if !found {
			return "", fmt.Errorf("circuits directory not found in any expected location")
		}
	}

	return dir, nil
}

// zkInitCallback is the lazy loading callback for ZK circuits
func zkInitCallback(algorithmID uint8) bool {
	logger := client.GetLogger("zk-init", false)

	config, ok := circuitsRegistry[algorithmID]
	if !ok {
		logger.Error("Unknown algorithm ID for lazy loading",
			zap.Uint8("algorithmID", algorithmID))
		return false
	}

	logger.Info("Lazy loading ZK circuit",
		zap.String("algorithm", config.algorithmName),
		zap.Uint8("algorithmID", algorithmID))

	// Resolve circuits directory if not already done
	if circuitsDir == "" {
		var err error
		circuitsDir, err = resolveCircuitsDir()
		if err != nil {
			logger.Error("Failed to resolve circuits directory", zap.Error(err))
			return false
		}
	}

	// Read proving key
	pkPath := filepath.Join(circuitsDir, config.pkFile)
	pkData, err := os.ReadFile(pkPath)
	if err != nil {
		logger.Error("Failed to read proving key",
			zap.String("algorithm", config.algorithmName),
			zap.String("path", pkPath),
			zap.Error(err))
		return false
	}

	// Read R1CS
	r1csPath := filepath.Join(circuitsDir, config.r1csFile)
	r1csData, err := os.ReadFile(r1csPath)
	if err != nil {
		logger.Error("Failed to read R1CS",
			zap.String("algorithm", config.algorithmName),
			zap.String("path", r1csPath),
			zap.Error(err))
		return false
	}

	// Initialize the algorithm using the tracking wrapper
	success := client.InitAlgorithmWithTracking(algorithmID, pkData, r1csData)
	if !success {
		logger.Error("Failed to initialize algorithm",
			zap.String("algorithm", config.algorithmName))
		return false
	}

	logger.Info("Successfully lazy loaded ZK circuit",
		zap.String("algorithm", config.algorithmName),
		zap.Uint8("id", algorithmID),
		zap.Int("pk_size", len(pkData)),
		zap.Int("r1cs_size", len(r1csData)))

	return true
}

// setupZKLazyLoading sets up the lazy loading callback for ZK circuits
func setupZKLazyLoading(logger *shared.Logger) error {
	// Resolve and validate circuits directory exists
	var err error
	circuitsDir, err = resolveCircuitsDir()
	if err != nil {
		return err
	}

	logger.Info("Setting up ZK lazy loading", zap.String("circuits_dir", circuitsDir))

	// Set the lazy loading callback
	client.SetZKInitCallback(func(algorithmID uint8) <-chan bool {
		resultCh := make(chan bool, 1)
		go func() {
			resultCh <- zkInitCallback(algorithmID)
		}()
		return resultCh
	})

	logger.Info("ZK lazy loading configured - circuits will be loaded on demand")
	return nil
}

func main() {

	// Initialize logger
	logger := client.GetLogger("client", false)

	defer logger.Sync()

	// Setup lazy loading for ZK circuits (loaded on demand when needed)
	if err := setupZKLazyLoading(logger); err != nil {
		logger.Error("Failed to setup ZK lazy loading", zap.Error(err))
		log.Fatalf("ZK lazy loading setup failed: %v", err)
	}
	logger.Sync()

	// Show usage if requested
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("Usage: demo_standalone --router-url=URL [tls_version] [cipher_suite] [attestor_url]")
		fmt.Println("  --router-url: Router base URL (required), e.g. http://localhost:8090 or https://tee.reclaimprotocol.org")
		fmt.Println("  tls_version:  Force TLS version: 1.2, 1.3, or empty for auto")
		fmt.Println("  cipher_suite: Force cipher suite: hex (e.g. 0xc02f) or name")
		fmt.Println("  attestor_url: Attestor WebSocket URL (default: ws://localhost:8001/ws)")
		fmt.Println("\nExamples:")
		fmt.Println("  demo_standalone --router-url=http://localhost:8090")
		fmt.Println("  demo_standalone --router-url=https://tee.reclaimprotocol.org 1.2 0xc02f")
		os.Exit(0)
	}

	logger.Info("=== Client ===")

	attestorURL := "ws://localhost:8001/ws"
	forceTLSVersion := ""
	forceCipherSuite := ""
	routerURL := ""

	// Pull out --router-url=... from args; the remainder is positional.
	positional := make([]string, 0, len(os.Args))
	for i, a := range os.Args {
		if i == 0 {
			positional = append(positional, a)
			continue
		}
		if after, ok := strings.CutPrefix(a, "--router-url="); ok {
			routerURL = after
			continue
		}
		positional = append(positional, a)
	}

	if routerURL == "" {
		fmt.Println("error: --router-url=URL is required")
		fmt.Println("run with --help for usage")
		os.Exit(1)
	}

	if len(positional) > 1 {
		forceTLSVersion = positional[1]
		if forceTLSVersion != "1.2" && forceTLSVersion != "1.3" && forceTLSVersion != "" {
			logger.Error("Invalid TLS version", zap.String("version", forceTLSVersion))
			fmt.Printf("Invalid TLS version '%s'. Use '1.2', '1.3', or omit for auto-negotiation\n", forceTLSVersion)
			os.Exit(1)
		}
	}

	if len(positional) > 2 {
		forceCipherSuite = positional[2]
		if forceCipherSuite != "" && !isValidCipherSuite(forceCipherSuite) {
			logger.Error("Invalid cipher suite", zap.String("cipher_suite", forceCipherSuite))
			fmt.Printf("Invalid cipher suite '%s'. Use hex format (e.g. '0xc02f') or valid name\n", forceCipherSuite)
			os.Exit(1)
		}
	}

	if len(positional) > 3 {
		attestorURL = positional[3]
		logger.Info("Using custom attestor URL", zap.String("attestor_url", attestorURL))
	}

	logger.Info("Starting Client", zap.String("router_url", routerURL), zap.String("attestor_url", attestorURL))
	if forceTLSVersion != "" {
		logger.Info("Forcing TLS version", zap.String("version", forceTLSVersion))
	} else {
		logger.Info("TLS version auto-negotiation enabled")
	}
	if forceCipherSuite != "" {
		logger.Info("Forcing cipher suite", zap.String("cipher_suite", forceCipherSuite))
	} else {
		logger.Info("Cipher suite auto-negotiation enabled")
	}

	providerParams := &providers.HTTPProviderParams{
		URL:    "https://example.com/",
		Method: "GET",
		// GeoLocation: "US",
		ResponseMatches: []providers.ResponseMatch{
			{
				Value: "{{addr}}",
				Type:  "contains",
			},
		},
		ResponseRedactions: []providers.ResponseRedaction{
			{
				XPath: "/html/body/div/p[2]/a",
				Regex: "href=\"https://(?<addr>iana.org)/.*?\"",
				Hash:  providers.HASH_TYPE_OPRF_MPC, // Use MPC OPRF instead of client-side TOPRF
			},
		},
		ParamValues: map[string]string{
			"addr": "iana.org",
		},
	}

	secretParams := &providers.HTTPProviderSecretParams{
		Headers: map[string]string{
			"accept": "application/json, text/plain, */*",
		},
	}

	// Create provider data structure for JSON encoding (production format)
	providerData := client.ProviderRequestData{
		Name:         "http",
		Params:       providerParams,
		SecretParams: secretParams,
		Context:      `{"test":"demo","source":"standalone"}`,
	}

	logger.Info("Demo provider params configured")

	config := client.ClientConfig{
		RouterURL:        routerURL,
		AttestorURL:      attestorURL,
		Timeout:          client.DefaultConnectionTimeout,
		Mode:             client.ModeAuto,
		ForceTLSVersion:  forceTLSVersion,
		ForceCipherSuite: forceCipherSuite,
	}

	reclaimClient, err := client.NewReclaimClient(config)
	if err != nil {
		logger.Error("Failed to create reclaim client", zap.Error(err))
		log.Fatalf("Failed to create reclaim client: %v", err)
	}
	defer reclaimClient.Close()

	// Execute the complete protocol with progress reporting
	fmt.Println("\n🚀 Starting complete protocol execution...")
	result, err := reclaimClient.ExecuteCompleteProtocol(&providerData)
	if err != nil {
		fmt.Printf("\n🔴 Complete protocol execution failed: %v\n", err)
		log.Fatalf("Cannot execute complete protocol: %v", err)
	}

	// Display final results
	fmt.Printf("\n✅ Protocol completed successfully! Claim ID: %s\n", result.Claim.Identifier)
	fmt.Printf("🎯 Provider: %s\n", result.Claim.Provider)
	fmt.Printf("🔏 Attestor: %s\n", result.Signature.AttestorAddress)

	// Demonstrate accessing protocol results
	fmt.Println("\n===== PROTOCOL RESULTS =====")

	// Get complete protocol results
	protocolResult, err := reclaimClient.GetProtocolResult()
	if err != nil {
		fmt.Printf("❌ Error getting protocol result: %v\n", err)
	} else {
		fmt.Printf("✅ Protocol Success: %v\n", protocolResult.Success)
		fmt.Printf("📋 Session ID: %s\n", protocolResult.SessionID)
		fmt.Printf("🎯 Target: %s:%d\n", protocolResult.RequestTarget, protocolResult.RequestPort)
		fmt.Printf("⏱️  Duration: %v\n", protocolResult.CompletionTime.Sub(protocolResult.StartTime))

		if !protocolResult.Success && protocolResult.ErrorMessage != "" {
			fmt.Printf("❌ Error: %s\n", protocolResult.ErrorMessage)
		}
	}

	// Get transcript results
	transcripts, err := reclaimClient.GetTranscripts()
	if err != nil {
		fmt.Printf("❌ Error getting transcripts: %v\n", err)
	} else {
		fmt.Printf("\n📜 TRANSCRIPT RESULTS:\n")
		fmt.Printf("   Both Received: %v\n", transcripts.BothReceived)
		fmt.Printf("   Both Valid: %v\n", transcripts.BothSignaturesValid)

		if transcripts.TEEK != nil {
			totalTEEKBytes := 0
			for _, data := range transcripts.TEEK.Data {
				totalTEEKBytes += len(data)
			}
			fmt.Printf("   TEE_K: %d data streams, %d bytes total\n",
				len(transcripts.TEEK.Data), totalTEEKBytes)
		}

		if transcripts.TEET != nil {
			totalTEETBytes := 0
			for _, data := range transcripts.TEET.Data {
				totalTEETBytes += len(data)
			}
			fmt.Printf("   TEE_T: %d data streams, %d bytes total\n",
				len(transcripts.TEET.Data), totalTEETBytes)
		}
	}

	// Get validation results
	validation, err := reclaimClient.GetValidationResults()
	if err != nil {
		fmt.Printf("❌ Error getting validation results: %v\n", err)
	} else {
		fmt.Printf("\n🔍 VALIDATION RESULTS:\n")
		fmt.Printf("   All Validations Passed: %v\n", validation.AllValidationsPassed)
		fmt.Printf("   Summary: %s\n", validation.ValidationSummary)
		fmt.Printf("   Transcript Validation: %v\n", validation.TranscriptValidation.OverallValid)
	}

	// Get response results
	response, err := reclaimClient.GetResponseResults()
	if err != nil {
		fmt.Printf("❌ Error getting response results: %v\n", err)
	} else {
		fmt.Printf("\n📨 RESPONSE RESULTS:\n")
		fmt.Printf("   Response Received: %v\n", response.ResponseReceived)
		fmt.Printf("   Callback Executed: %v\n", response.CallbackExecuted)
		fmt.Printf("   Decryption Successful: %v\n", response.DecryptionSuccessful)
		fmt.Printf("   Data Size: %d bytes\n", response.DecryptedDataSize)
	}

	// Display OPRF results if any were processed
	oprfRanges := reclaimClient.Client.GetOPRFRanges()
	if len(oprfRanges) > 0 {
		fmt.Printf("\n📊 OPRF Results Summary:\n")
		for start, oprfData := range oprfRanges {
			fmt.Printf("   Range [%d:%d]:\n", start, start+oprfData.Length)
			fmt.Printf("     - Data: %s\n", string(oprfData.Data[:min(32, len(oprfData.Data))]))
			fmt.Printf("     - OPRF Output: %x\n", oprfData.FinalOutput[:min(16, len(oprfData.FinalOutput))])
			fmt.Printf("     - ZK Proof: %d bytes\n", len(oprfData.ZKProof))
		}
	}

}

// isValidCipherSuite validates cipher suite format and name
func isValidCipherSuite(cipherSuite string) bool {
	return minitls.IsValidCipherSuite(cipherSuite)
}
