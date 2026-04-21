// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

package log

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// zapLogger is the package-level zap sugared logger.
var zapLogger *zap.SugaredLogger

// globalLogLevel is the active log level (debug, info, warn, error).
var globalLogLevel string = "info"

// globalLogFile is the log destination path, or "stdout".
var globalLogFile string = "stdout"

// LogHook, if set, is called for every log entry with the level and message.
// Set this after the gRPC exporter is initialized to forward logs over gRPC.
var LogHook func(level, message string)

func init() {
	initLogger()
}

// customTimeEncoder formats times as "YYYY-MM-DD HH:MM:SS.microseconds".
func customTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05.000000"))
}

func getLogLevel(level string) zapcore.Level {
	switch strings.ToLower(level) {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

func initLogger() {
	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(getLogLevel(globalLogLevel)),
		Development: false,
		Encoding:    "console",
		OutputPaths: []string{"stdout"},
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "level",
			NameKey:        "logger",
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			EncodeTime:     customTimeEncoder,
			EncodeLevel:    zapcore.CapitalColorLevelEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
		},
	}

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}

	zapLogger = logger.Sugar()
}

// SetLogger configures the logger with specified output file and log level
// Log files are created with 0600 permissions. The level must be
// "debug", "info", "warn", or "error" (case-insensitive); defaults to "info".
func SetLogger(logFile string, level string) {
	globalLogLevel = level

	if logFile == "" || logFile == "stdout" {
		globalLogFile = "stdout"
	} else {
		absPath, err := filepath.Abs(logFile)
		if err != nil {
			panic(fmt.Sprintf("Invalid log file path: %v", err))
		}
		globalLogFile = absPath

		if dir := filepath.Dir(absPath); dir != "." {
			if err := os.MkdirAll(dir, 0750); err != nil {
				panic(fmt.Sprintf("Failed to create log directory: %v", err))
			}
		}

		// #nosec G304 - absPath is validated and sanitized by filepath.Abs
		file, err := os.OpenFile(absPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			panic(fmt.Sprintf("Failed to open log file: %v", err))
		}
		if err := file.Close(); err != nil {
			panic(fmt.Sprintf("Failed to close log file: %v", err))
		}
	}

	config := zap.Config{
		Level:       zap.NewAtomicLevelAt(getLogLevel(level)),
		Development: false,
		Sampling: &zap.SamplingConfig{
			Initial:    3,
			Thereafter: 10,
		},
		Encoding:         "console",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	config.EncoderConfig.EncodeTime = customTimeEncoder
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.LevelKey = "level"
	config.EncoderConfig.NameKey = "logger"
	config.EncoderConfig.TimeKey = "time"
	config.EncoderConfig.CallerKey = ""
	config.EncoderConfig.StacktraceKey = "stacktrace"
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.EncoderConfig.EncodeDuration = zapcore.SecondsDurationEncoder

	if globalLogFile != "stdout" {
		config.OutputPaths = []string{globalLogFile}
	}

	logger, err := config.Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build logger: %v", err))
	}

	zapLogger = logger.Sugar()

	if globalLogFile != "stdout" {
		Printf("[Logger] Log file: %s", globalLogFile)
	}
	Printf("[Logger] Log level: %s", level)
}

// Deprecated: use SetLogger instead.
func SetLogFile(logFile string) {
	SetLogger(logFile, globalLogLevel)
}

// Deprecated: use SetLogger instead.
func SetLogLevel(level string) {
	SetLogger(globalLogFile, level)
}

func hook(level, message string) {
	if LogHook != nil {
		LogHook(level, message)
	}
}

func Print(message string) { zapLogger.Info(message); hook("info", message) }
func Printf(message string, args ...interface{}) {
	msg := fmt.Sprintf(message, args...)
	zapLogger.Info(msg)
	hook("info", msg)
}
func Debug(message string) { zapLogger.Debug(message); hook("debug", message) }
func Debugf(message string, args ...interface{}) {
	msg := fmt.Sprintf(message, args...)
	zapLogger.Debug(msg)
	hook("debug", msg)
}
func Err(message string) { zapLogger.Error(message); hook("error", message) }
func Errf(message string, args ...interface{}) {
	msg := fmt.Sprintf(message, args...)
	zapLogger.Error(msg)
	hook("error", msg)
}
func Warn(message string) { zapLogger.Warn(message); hook("warn", message) }
func Warnf(message string, args ...interface{}) {
	msg := fmt.Sprintf(message, args...)
	zapLogger.Warn(msg)
	hook("warn", msg)
}
