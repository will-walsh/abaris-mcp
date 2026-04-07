// Package infra contains infrastructure adapters that implement domain
// interfaces. Nothing in internal/domain imports this package.
package infra

import (
	"log/slog"
	"os"
	"strings"

	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// SlogLogger implements domain.Logger using Go's structured slog package.
// Output is always JSON to stdout. Log level is controlled by the
// ABARIS_LOG_LEVEL environment variable (DEBUG, INFO, WARN, ERROR).
// Defaults to INFO if the variable is absent or unrecognised.
//
// IMPORTANT: callers must never pass raw tokens, SAML assertions, passwords,
// or secret values as log arguments. This adapter does not scrub values.
type SlogLogger struct {
	logger *slog.Logger
}

// NewSlogLogger creates a SlogLogger reading the log level from the
// ABARIS_LOG_LEVEL environment variable.
func NewSlogLogger() *SlogLogger {
	level := levelFromEnv()
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return &SlogLogger{logger: slog.New(handler)}
}

func (l *SlogLogger) Info(msg string, args ...any)  { l.logger.Info(msg, args...) }
func (l *SlogLogger) Warn(msg string, args ...any)  { l.logger.Warn(msg, args...) }
func (l *SlogLogger) Error(msg string, args ...any) { l.logger.Error(msg, args...) }
func (l *SlogLogger) Debug(msg string, args ...any) { l.logger.Debug(msg, args...) }

// compile-time interface check
var _ domain.Logger = (*SlogLogger)(nil)

func levelFromEnv() slog.Level {
	switch strings.ToUpper(os.Getenv("ABARIS_LOG_LEVEL")) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
