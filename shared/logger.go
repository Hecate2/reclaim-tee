//go:build !mobile

package shared

import (
	"context"
	"os"
	"sync"

	"cloud.google.com/go/logging"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LoggerConfig holds the configuration for the logger
type LoggerConfig struct {
	ServiceName string // "tee_t" or "tee_k"
	EnclaveMode bool   // true if running in enclave
	Development bool   // true for development mode
}

// Logger wraps zap.Logger with additional context
type Logger struct {
	*zap.Logger
	serviceName string
	enclaveMode bool
}

// gcpCore implements zapcore.Core and writes to GCP Cloud Logging
type gcpCore struct {
	logger      *logging.Logger
	serviceName string
	enclaveMode bool
	fields      []zap.Field
}

func (c *gcpCore) Enabled(level zapcore.Level) bool {
	return level >= zapcore.InfoLevel // Only INFO and above in production
}

func (c *gcpCore) With(fields []zapcore.Field) zapcore.Core {
	// Convert zapcore.Field to zap.Field (they're compatible)
	zapFields := make([]zap.Field, len(fields))
	for i, f := range fields {
		zapFields[i] = zap.Field(f)
	}
	return &gcpCore{
		logger:      c.logger,
		serviceName: c.serviceName,
		enclaveMode: c.enclaveMode,
		fields:      append(c.fields, zapFields...),
	}
}

func (c *gcpCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c)
	}
	return checked
}

func (c *gcpCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	// Convert zap level to GCP severity
	var severity logging.Severity
	switch entry.Level {
	case zapcore.DebugLevel:
		severity = logging.Debug
	case zapcore.InfoLevel:
		severity = logging.Info
	case zapcore.WarnLevel:
		severity = logging.Warning
	case zapcore.ErrorLevel:
		severity = logging.Error
	case zapcore.DPanicLevel, zapcore.PanicLevel, zapcore.FatalLevel:
		severity = logging.Critical
	default:
		severity = logging.Default
	}

	// Build payload from fields
	payload := make(map[string]any)
	payload["message"] = entry.Message
	payload["service"] = c.serviceName
	payload["enclave_mode"] = c.enclaveMode

	// Add persistent fields
	for _, f := range c.fields {
		addFieldToPayload(payload, f)
	}

	// Add entry fields
	for _, f := range fields {
		addFieldToPayload(payload, zap.Field(f))
	}

	// Log to GCP
	c.logger.Log(logging.Entry{
		Severity: severity,
		Payload:  payload,
	})

	return nil
}

func (c *gcpCore) Sync() error {
	return c.logger.Flush()
}

func addFieldToPayload(payload map[string]any, field zap.Field) {
	switch field.Type {
	case zapcore.StringType:
		payload[field.Key] = field.String
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		payload[field.Key] = field.Integer
	case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
		payload[field.Key] = field.Integer
	case zapcore.Float64Type, zapcore.Float32Type:
		payload[field.Key] = field.Integer // zap stores floats as int64
	case zapcore.BoolType:
		payload[field.Key] = field.Integer != 0
	case zapcore.ErrorType:
		if field.Interface != nil {
			payload[field.Key] = field.Interface.(error).Error()
		}
	default:
		payload[field.Key] = field.Interface
	}
}

// NewLogger creates a new logger instance based on the configuration
func NewLogger(config LoggerConfig) (*Logger, error) {
	var zapLogger *zap.Logger
	var err error

	// GCP cloud logging for enclave mode
	if config.EnclaveMode {
		projectID := os.Getenv("GCP_PROJECT_ID")
		if projectID == "" {
			projectID = os.Getenv("GOOGLE_PROJECT_ID") // Fallback
		}

		if projectID != "" {
			// Create GCP Cloud Logging client
			ctx := context.Background()
			client, err := logging.NewClient(ctx, projectID)
			if err != nil {
				// Fall back to console logging if GCP client fails
				zapConfig := zap.NewProductionConfig()
				zapConfig.EncoderConfig.TimeKey = "timestamp"
				zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
				zapLogger, _ = zapConfig.Build()
			} else {
				// Create GCP logger with service name as log name
				gcpLogger := client.Logger(config.ServiceName)

				// Create zap core that writes to GCP
				core := &gcpCore{
					logger:      gcpLogger,
					serviceName: config.ServiceName,
					enclaveMode: config.EnclaveMode,
				}

				zapLogger = zap.New(core)
			}
		} else {
			// No project ID, fall back to console
			zapConfig := zap.NewProductionConfig()
			zapConfig.EncoderConfig.TimeKey = "timestamp"
			zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
			zapLogger, err = zapConfig.Build()
		}
	} else if config.EnclaveMode {
		zapConfig := zap.NewProductionConfig()
		// Use human-readable timestamp format
		zapConfig.EncoderConfig.TimeKey = "timestamp"
		zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		zapLogger, err = zapConfig.Build()
	} else if config.Development {
		// Development mode: console logging with debug level and human-readable timestamps
		zapConfig := zap.NewDevelopmentConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		// Use human-readable timestamp format
		zapConfig.EncoderConfig.TimeKey = "timestamp"
		zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		zapLogger, err = zapConfig.Build()
	} else {
		// Standalone production mode: structured JSON logging with human-readable timestamps
		zapConfig := zap.NewProductionConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		// Use human-readable timestamp format
		zapConfig.EncoderConfig.TimeKey = "timestamp"
		zapConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		zapLogger, err = zapConfig.Build()
	}

	if err != nil {
		return nil, err
	}

	// Add service-specific fields
	zapLogger = zapLogger.With(
		zap.String("service", config.ServiceName),
		zap.Bool("enclave_mode", config.EnclaveMode),
	)

	return &Logger{
		Logger:      zapLogger,
		serviceName: config.ServiceName,
		enclaveMode: config.EnclaveMode,
	}, nil
}

// NewLoggerFromEnv creates a logger using environment variables
func NewLoggerFromEnv(serviceName string) (*Logger, error) {
	config := LoggerConfig{
		ServiceName: serviceName,
		EnclaveMode: GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Development: GetEnvOrDefault("DEVELOPMENT", "false") == "true",
	}
	return NewLogger(config)
}

// TruncateSessionID returns first 8 chars of session ID for logging (security)
func TruncateSessionID(sessionID string) string {
	if len(sessionID) <= 8 {
		return sessionID
	}
	return sessionID[:8]
}

// Session-aware logging methods (truncates session ID for security)
func (l *Logger) WithSession(sessionID string) *zap.Logger {
	if sessionID == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("sid", TruncateSessionID(sessionID)))
}

// WithSessionFull logs full session ID - use only when absolutely necessary
func (l *Logger) WithSessionFull(sessionID string) *zap.Logger {
	if sessionID == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("session_id", sessionID))
}

// Connection-aware logging methods - DEPRECATED: don't log remote addresses
func (l *Logger) WithConnection(remoteAddr string) *zap.Logger {
	// No longer log remote addresses for privacy
	return l.Logger
}

// Protocol-aware logging methods
func (l *Logger) WithMessageType(msgType string) *zap.Logger {
	if msgType == "" {
		return l.Logger
	}
	return l.Logger.With(zap.String("message_type", msgType))
}

// Crypto-aware logging methods
func (l *Logger) WithCryptoOp(operation string) *zap.Logger {
	return l.Logger.With(zap.String("crypto_operation", operation))
}

// Critical error logging - always logs even in enclave mode
func (l *Logger) Critical(msg string, fields ...zap.Field) {
	// Critical errors are always logged regardless of mode
	l.Logger.Error(msg, append(fields, zap.Bool("critical", true))...)
}

// Security event logging - for security-relevant events
func (l *Logger) Security(msg string, fields ...zap.Field) {
	// Security events are always logged regardless of mode
	l.Logger.Warn(msg, append(fields, zap.Bool("security_event", true))...)
}

// Session termination logging
func (l *Logger) SessionTerminated(sessionID string, reason string, fields ...zap.Field) {
	baseFields := []zap.Field{
		zap.String("sid", TruncateSessionID(sessionID)),
		zap.String("termination_reason", reason),
		zap.Bool("session_terminated", true),
	}
	l.Logger.Error("Session terminated", append(baseFields, fields...)...)
}

// Conditional warning logging - respects enclave mode settings
func (l *Logger) WarnIf(msg string, fields ...zap.Field) {
	if !l.enclaveMode {
		l.Logger.Warn(msg, fields...)
	}
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.Logger.Sync()
}

// Close closes the logger and flushes any buffered entries
func (l *Logger) Close() error {
	return l.Logger.Sync()
}

// Global logger instances
var (
	DefaultLogger     *Logger
	teetLoggerOnce    sync.Once
	teekLoggerOnce    sync.Once
	defaultTEETLogger *Logger
	defaultTEEKLogger *Logger
)

// GetTEETLogger returns the default TEE_T logger
func GetTEETLogger() *Logger {
	if DefaultLogger != nil {
		return DefaultLogger
	}
	teetLoggerOnce.Do(func() {
		defaultTEETLogger, _ = NewLoggerFromEnv("tee_t")
	})
	return defaultTEETLogger
}

// GetTEEKLogger returns the default TEE_K logger
func GetTEEKLogger() *Logger {
	if DefaultLogger != nil {
		return DefaultLogger
	}
	teekLoggerOnce.Do(func() {
		defaultTEEKLogger, _ = NewLoggerFromEnv("tee_k")
	})
	return defaultTEEKLogger
}

func NewNopLogger() *Logger {
	return &Logger{
		Logger: zap.NewNop(),
	}
}
