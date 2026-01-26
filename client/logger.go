package client

import (
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

var sharedZapLogger *zap.Logger // For receiving shared logger from main package

// GetLogger creates a logger for the libclient package
func GetLogger(serviceName string, isEnclaveMode bool) *shared.Logger {
	// Check if we have a shared logger from main package
	if sharedZapLogger != nil {
		return &shared.Logger{
			Logger: sharedZapLogger.With(zap.String("service", serviceName)),
		}
	}

	// Fallback to standard logger if no shared logger available
	development := true
	logger, _ := shared.NewLogger(shared.LoggerConfig{
		ServiceName: serviceName,
		EnclaveMode: isEnclaveMode,
		Development: development,
	})
	logger.Logger = logger.Logger.With(
		zap.String("source", "TEE-CLIENT"),
	)
	return logger
}

// SetSharedLogger allows the main package to share its Flutter-enabled logger
func SetSharedLogger(zapLogger *zap.Logger) {
	sharedZapLogger = zapLogger
}
