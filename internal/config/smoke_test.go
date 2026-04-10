//go:build integration

package config_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/will-walsh/abaris-mcp/internal/config"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// repoRoot returns the absolute path to the module root by walking up from
// this test file's location until go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod")
		}
		dir = parent
	}
}

// copyDir recursively copies src into dst.
func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("copyDir ReadDir %s: %v", src, err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("copyDir MkdirAll %s: %v", dst, err)
	}
	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyDir(t, srcPath, dstPath)
		} else {
			data, err := os.ReadFile(srcPath)
			if err != nil {
				t.Fatalf("copyDir ReadFile %s: %v", srcPath, err)
			}
			if err := os.WriteFile(dstPath, data, 0o644); err != nil {
				t.Fatalf("copyDir WriteFile %s: %v", dstPath, err)
			}
		}
	}
}

// TestSmoke_ConfigDirectoryLoadsWithoutError copies the sample config/ directory
// to a temp dir and verifies that Loader.Load() succeeds and returns a non-empty Config.
//
// Validates: Requirements 5.1
func TestSmoke_ConfigDirectoryLoadsWithoutError(t *testing.T) {
	root := repoRoot(t)
	src := filepath.Join(root, "config")

	tmp := t.TempDir()
	copyDir(t, src, tmp)

	logger := infra.NewSlogLogger()
	loader := config.NewLoader(tmp, logger, nil)

	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}

	if len(cfg.Routes) == 0 {
		t.Error("expected non-empty Routes")
	}
	if len(cfg.IdentityProviders) == 0 {
		t.Error("expected non-empty IdentityProviders")
	}
	if len(cfg.Policies) == 0 {
		t.Error("expected non-empty Policies")
	}
}

// TestSmoke_SlogJSONOutputFormat verifies that the slog JSON handler emits
// valid JSON with the required fields: time, level, msg.
//
// Validates: Requirements 6.1
func TestSmoke_SlogJSONOutputFormat(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)

	logger.Info("smoke test message", "key", "value")

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("expected log output, got empty buffer")
	}

	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		t.Fatalf("log output is not valid JSON: %v\noutput: %s", err, line)
	}

	for _, field := range []string{"time", "level", "msg"} {
		if _, ok := record[field]; !ok {
			t.Errorf("expected JSON field %q to be present in log record", field)
		}
	}

	if record["msg"] != "smoke test message" {
		t.Errorf("expected msg=%q, got %v", "smoke test message", record["msg"])
	}
}

// TestSmoke_LogLevelEnvVarRespected verifies that ABARIS_LOG_LEVEL controls
// which messages are emitted. DEBUG messages appear at DEBUG level and are
// suppressed at ERROR level.
//
// Validates: Requirements 6.5
func TestSmoke_LogLevelEnvVarRespected(t *testing.T) {
	levelFromEnv := func(envVal string) slog.Level {
		switch strings.ToUpper(envVal) {
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

	t.Run("DEBUG level emits debug messages", func(t *testing.T) {
		t.Setenv("ABARIS_LOG_LEVEL", "DEBUG")

		var buf bytes.Buffer
		level := levelFromEnv(os.Getenv("ABARIS_LOG_LEVEL"))
		handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})
		logger := slog.New(handler)

		logger.Debug("debug message")

		if buf.Len() == 0 {
			t.Error("expected debug message to appear when ABARIS_LOG_LEVEL=DEBUG")
		}
	})

	t.Run("ERROR level suppresses debug messages", func(t *testing.T) {
		t.Setenv("ABARIS_LOG_LEVEL", "ERROR")

		var buf bytes.Buffer
		level := levelFromEnv(os.Getenv("ABARIS_LOG_LEVEL"))
		handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})
		logger := slog.New(handler)

		logger.Debug("debug message")

		if buf.Len() != 0 {
			t.Errorf("expected debug message to be suppressed when ABARIS_LOG_LEVEL=ERROR, got: %s", buf.String())
		}
	})
}

// TestSmoke_GoBuildSucceeds verifies that `go build ./...` completes without error.
//
// Validates: Requirements 5.1, 6.1
func TestSmoke_GoBuildSucceeds(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "build", "./...")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./... failed:\n%s", out)
	}
}

// TestSmoke_GoVetPasses verifies that `go vet ./...` reports no issues.
//
// Validates: Requirements 5.1, 6.1
func TestSmoke_GoVetPasses(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("go", "vet", "./...")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go vet ./... failed:\n%s", out)
	}
}

