package main

/*
#include <stdlib.h>

// Function pointer type for Flutter callback with progress support
typedef void (*LogCallback)(const char* level, const char* message, const char* fields, int progress_percentage, const char* progress_description);

// Global callback storage
static LogCallback flutter_log_callback = NULL;

// Helper to call the callback - made static inline to prevent duplicate symbols
static inline void call_flutter_log(const char* level, const char* message, const char* fields, int progress_percentage, const char* progress_description) {
    if (flutter_log_callback != NULL) {
        flutter_log_callback(level, message, fields, progress_percentage, progress_description);
    }
}

// Store the callback
static void store_log_callback(LogCallback callback) {
    flutter_log_callback = callback;
}
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"unsafe"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	callbackMutex   sync.RWMutex
	callbackEnabled bool = false
)

// Buffer logs emitted before Flutter registers the callback
type pendingLogEntry struct {
	level               string
	message             string
	fieldsJSON          string
	progressPercentage  int
	progressDescription string
}

var pendingLogs []pendingLogEntry

const maxPendingLogs = 200

// FlutterCore implements zapcore.Core to forward logs to Flutter
type FlutterCore struct {
	zapcore.LevelEnabler
	mu sync.Mutex
}

// NewFlutterCore creates a new Flutter logging core
func NewFlutterCore(enabler zapcore.LevelEnabler) *FlutterCore {
	return &FlutterCore{
		LevelEnabler: enabler,
	}
}

// With adds structured context to the logger
func (c *FlutterCore) With(fields []zapcore.Field) zapcore.Core {
	// Return a new core with the same settings
	return &FlutterCore{
		LevelEnabler: c.LevelEnabler,
	}
}

// Check determines whether the supplied Entry should be logged
func (c *FlutterCore) Check(entry zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return ce.AddCore(entry, c)
	}
	return ce
}

// Write serializes the Entry and sends it to Flutter
func (c *FlutterCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Convert level to string
	levelStr := entry.Level.String()

	// Get the message
	message := entry.Message

	// Extract progress fields if present
	progressPercentage := -1
	progressDescription := ""

	// Encode fields to JSON
	fieldsMap := make(map[string]interface{})
	for _, field := range fields {
		// Check for progress fields and extract them separately
		if field.Key == "progress_percentage" {
			if field.Type == zapcore.Int64Type || field.Type == zapcore.Int32Type ||
				field.Type == zapcore.Int16Type || field.Type == zapcore.Int8Type {
				progressPercentage = int(field.Integer)
				continue // Don't add to fieldsMap
			}
		}
		if field.Key == "progress_description" && field.Type == zapcore.StringType {
			progressDescription = field.String
			continue // Don't add to fieldsMap
		}

		// Handle regular fields
		switch field.Type {
		case zapcore.StringType:
			fieldsMap[field.Key] = field.String
		case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
			fieldsMap[field.Key] = field.Integer
		case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
			fieldsMap[field.Key] = uint64(field.Integer)
		case zapcore.Float64Type, zapcore.Float32Type:
			fieldsMap[field.Key] = float64(field.Integer)
		case zapcore.BoolType:
			fieldsMap[field.Key] = field.Integer == 1
		case zapcore.ErrorType:
			if err, ok := field.Interface.(error); ok {
				fieldsMap[field.Key] = err.Error()
			}
		default:
			fieldsMap[field.Key] = fmt.Sprint(field.Interface)
		}
	}

	// Add entry metadata
	fieldsMap["caller"] = entry.Caller.String()
	fieldsMap["timestamp"] = entry.Time.Format("2006-01-02T15:04:05.000Z07:00")

	// Add service name if available
	if entry.LoggerName != "" {
		fieldsMap["logger"] = entry.LoggerName
	}

	fieldsJSON, _ := json.Marshal(fieldsMap)

	// Determine if callback is enabled
	callbackMutex.RLock()
	enabled := callbackEnabled
	callbackMutex.RUnlock()

	if !enabled {
		// Buffer until callback is registered
		callbackMutex.Lock()
		if len(pendingLogs) >= maxPendingLogs {
			pendingLogs = pendingLogs[1:]
		}
		pendingLogs = append(pendingLogs, pendingLogEntry{
			level:               levelStr,
			message:             message,
			fieldsJSON:          string(fieldsJSON),
			progressPercentage:  progressPercentage,
			progressDescription: progressDescription,
		})
		callbackMutex.Unlock()
		return nil
	}

	// Send to Flutter (keep strings alive)
	levelC := C.CString(levelStr)
	messageC := C.CString(message)
	fieldsC := C.CString(string(fieldsJSON))
	progressDescC := C.CString(progressDescription)

	C.call_flutter_log(levelC, messageC, fieldsC, C.int(progressPercentage), progressDescC)

	return nil
}

// Sync flushes buffered logs (if any)
func (c *FlutterCore) Sync() error {
	return nil
}

// CreateLoggerWithFlutterCallback creates a Zap logger that includes Flutter callback support
func CreateLoggerWithFlutterCallback(serviceName string, development bool) (*zap.Logger, error) {
	// Base encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Console core for local logging
	var consoleCore zapcore.Core
	if development {
		consoleEncoder := zapcore.NewConsoleEncoder(encoderConfig)
		consoleCore = zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapcore.DebugLevel)
	} else {
		jsonEncoder := zapcore.NewJSONEncoder(encoderConfig)
		consoleCore = zapcore.NewCore(jsonEncoder, zapcore.AddSync(os.Stdout), zapcore.InfoLevel)
	}

	// Flutter core for callback logging
	flutterCore := NewFlutterCore(zapcore.DebugLevel)

	// Combine cores
	core := zapcore.NewTee(consoleCore, flutterCore)

	// Create logger with additional context
	logger := zap.New(core,
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	// Add service context
	logger = logger.With(
		zap.String("service", serviceName),
	)

	return logger, nil
}

//export set_log_callback
func set_log_callback(callback unsafe.Pointer) C.int {
	callbackMutex.Lock()

	if callback == nil {
		// Disable callback
		C.store_log_callback(nil)
		callbackEnabled = false
		callbackMutex.Unlock()
		if logger != nil {
			logger.Info("Flutter log callback disabled")
		}
		return 0
	}

	// Store and enable callback
	C.store_log_callback(C.LogCallback(callback))
	callbackEnabled = true
	callbackMutex.Unlock()

	if logger != nil {
		logger.Info("Flutter log callback enabled")
	}

	// Flush any buffered logs
	callbackMutex.Lock()
	toFlush := pendingLogs
	pendingLogs = nil
	callbackMutex.Unlock()
	for _, e := range toFlush {
		lvl := C.CString(e.level)
		msg := C.CString(e.message)
		f := C.CString(e.fieldsJSON)
		pd := C.CString(e.progressDescription)
		C.call_flutter_log(lvl, msg, f, C.int(e.progressPercentage), pd)
	}
	return 1
}

//export clear_log_callback
func clear_log_callback() {
	callbackMutex.Lock()
	C.store_log_callback(nil)
	callbackEnabled = false
	callbackMutex.Unlock()

	if logger != nil {
		logger.Info("Flutter log callback cleared")
	}
}
