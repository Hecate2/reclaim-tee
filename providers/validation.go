package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
	"go.uber.org/zap"
)

// Cache of compiled schemas per provider name
var providerValidatorMap = make(map[string]*gojsonschema.Schema)
var validatorMutex sync.RWMutex

// Register AJV-like custom formats on init
func init() {
	// url: require scheme+host; allow template placeholders {{param}}
	gojsonschema.FormatCheckers.Add("url", urlFormatChecker{})
	// binary: only true for []byte (mirrors AJV Uint8Array/Buffer); strings return false
	gojsonschema.FormatCheckers.Add("binary", binaryFormatChecker{})
}

type urlFormatChecker struct{}

func (urlFormatChecker) IsFormat(input any) bool {
	str, ok := input.(string)
	if !ok {
		return false
	}
	if strings.Contains(str, "{{") && strings.Contains(str, "}}") {
		return true
	}
	u, err := url.Parse(str)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Host != ""
}

type binaryFormatChecker struct{}

func (binaryFormatChecker) IsFormat(input any) bool {
	_, ok := input.([]byte)
	return ok
}

// ValidateProviderParams mirrors TS assertValidateProviderParams
func ValidateProviderParams(providerName string, params any) error {
	logger.Info("Starting ValidateProviderParams", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.String("provider", providerName))

	validatorMutex.RLock()
	compiled, exists := providerValidatorMap[providerName]
	validatorMutex.RUnlock()

	logger.Debug("Schema cached status", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.Bool("cached", exists))

	if !exists {
		logger.Info("Step 1/2: Compiling schema for provider", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.Int("step", 1), zap.Int("total", 2))
		sch, ok := PROVIDER_SCHEMAS[providerName]
		if !ok {
			logger.Error("Unknown provider", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.String("provider", providerName))
			return fmt.Errorf("invalid provider name \"%s\"", providerName)
		}

		schemaLoader := gojsonschema.NewGoLoader(sch.Parameters)
		schema, err := gojsonschema.NewSchema(schemaLoader)
		if err != nil {
			logger.Error("Schema compilation failed", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.Error(err))
			return fmt.Errorf("failed to compile schema for %s: %w", providerName, err)
		}

		validatorMutex.Lock()
		providerValidatorMap[providerName] = schema
		validatorMutex.Unlock()
		compiled = schema
		logger.Debug("Schema compiled and cached", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"))
	}

	logger.Info("Step 2/2: Validating parameters against schema", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.Int("step", 2), zap.Int("total", 2))
	docLoader := gojsonschema.NewGoLoader(params)
	result, err := compiled.Validate(docLoader)
	if err != nil {
		logger.Error("Validation execution failed", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.Error(err))
		return fmt.Errorf("params validation failed: %w", err)
	}

	if !result.Valid() {
		logger.Error("Validation failed", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.Int("error_count", len(result.Errors())))
		// Aggregate errors similarly to TS message payload
		var b strings.Builder
		for i, e := range result.Errors() {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			b.WriteString(e.String())
			logger.Debug("Validation error detail", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"), zap.String("level", "verbose"), zap.Int("error_index", i+1), zap.String("error", e.String()))
		}
		return fmt.Errorf("params validation failed: %s", b.String())
	}

	logger.Info("Parameters validated successfully", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderParams"))
	return nil
}

// ValidateProviderSecretParams mirrors TS secret params validation
func ValidateProviderSecretParams(providerName string, secretParams any) error {
	logger.Info("Starting ValidateProviderSecretParams", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"), zap.String("provider", providerName))

	sch, ok := PROVIDER_SCHEMAS[providerName]
	if !ok {
		logger.Error("Unknown provider", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"), zap.String("provider", providerName))
		return fmt.Errorf("invalid provider name \"%s\"", providerName)
	}

	logger.Debug("Compiling secret parameters schema", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"))
	schemaLoader := gojsonschema.NewGoLoader(sch.SecretParameters)
	schema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		logger.Error("Secret schema compilation failed", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"), zap.Error(err))
		return fmt.Errorf("failed to compile secret schema for %s: %w", providerName, err)
	}

	logger.Debug("Validating secret parameters against schema", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"))
	docLoader := gojsonschema.NewGoLoader(secretParams)
	result, err := schema.Validate(docLoader)
	if err != nil {
		logger.Error("Secret validation execution failed", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"), zap.Error(err))
		return fmt.Errorf("secret params validation failed: %w", err)
	}
	if !result.Valid() {
		logger.Error("Secret validation failed", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"), zap.Int("error_count", len(result.Errors())))
		var b strings.Builder
		for i, e := range result.Errors() {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			b.WriteString(e.String())
			logger.Debug("Secret validation error detail", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"), zap.String("level", "verbose"), zap.Int("error_index", i+1), zap.String("error", e.String()))
		}
		return fmt.Errorf("secret params validation failed: %s", b.String())
	}
	logger.Info("Secret parameters validated successfully", zap.String("component", "Validation"), zap.String("operation", "ValidateProviderSecretParams"))
	return nil
}

// Helper function to validate and unmarshal JSON params in one step
func ValidateAndUnmarshalParams(providerName string, jsonData []byte, target any) error {
	var params any
	if err := json.Unmarshal(jsonData, &params); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := ValidateProviderParams(providerName, params); err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to unmarshal to target type: %w", err)
	}
	return nil
}

// Helper function for secret params
func ValidateAndUnmarshalSecretParams(providerName string, jsonData []byte, target any) error {
	var params any
	if err := json.Unmarshal(jsonData, &params); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := ValidateProviderSecretParams(providerName, params); err != nil {
		return err
	}
	if err := json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to unmarshal to target type: %w", err)
	}
	return nil
}
