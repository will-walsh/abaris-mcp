package infra_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/will-walsh/abaris-mcp/internal/domain"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// mockSecretsClient is a test double for SecretsClient.
type mockSecretsClient struct {
	secretString *string
	err          error
}

func (m *mockSecretsClient) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: m.secretString}, nil
}

func newAdapter(client infra.SecretsClient) *infra.SecretsManagerAdapter {
	return infra.NewSecretsManagerAdapterWithClient(client, infra.NewSlogLogger())
}

func TestGetServiceCredentials_Success(t *testing.T) {
	want := `{"username":"svc","password":"s3cr3t"}`
	adapter := newAdapter(&mockSecretsClient{secretString: aws.String(want)})

	got, err := adapter.GetServiceCredentials(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:svc-creds")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGetIDPClientSecret_Success(t *testing.T) {
	want := "client-secret-value"
	adapter := newAdapter(&mockSecretsClient{secretString: aws.String(want)})

	got, err := adapter.GetIDPClientSecret(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:idp-secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestGetServiceCredentials_ResourceNotFound(t *testing.T) {
	adapter := newAdapter(&mockSecretsClient{err: &types.ResourceNotFoundException{Message: aws.String("not found")}})

	_, err := adapter.GetServiceCredentials(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:missing")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got: %v", err)
	}
}

func TestGetServiceCredentials_Unreachable(t *testing.T) {
	adapter := newAdapter(&mockSecretsClient{err: errors.New("connection refused")})

	_, err := adapter.GetServiceCredentials(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:svc-creds")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got: %v", err)
	}
}

func TestGetIDPClientSecret_Unreachable(t *testing.T) {
	adapter := newAdapter(&mockSecretsClient{err: errors.New("timeout")})

	_, err := adapter.GetIDPClientSecret(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:idp-secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got: %v", err)
	}
}

func TestGetServiceCredentials_NilSecretString(t *testing.T) {
	// Secret exists but has no string value (binary secret)
	adapter := newAdapter(&mockSecretsClient{secretString: nil})

	_, err := adapter.GetServiceCredentials(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:binary-secret")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, domain.ErrServiceUnavailable) {
		t.Errorf("expected ErrServiceUnavailable, got: %v", err)
	}
}

// --- MustGetSecret / MustLoadSecrets tests ---

// mustGetSecretExitHelper is invoked as a subprocess by tests that need to
// verify os.Exit behaviour. The TEST_MUST_GET_SECRET_CASE env var selects
// which failure scenario to exercise.
func TestMustGetSecret_ExitHelper(t *testing.T) {
	// This test body only runs when invoked as a subprocess.
	scenario := os.Getenv("TEST_MUST_GET_SECRET_CASE")
	if scenario == "" {
		t.Skip("not a subprocess invocation")
	}

	var client infra.SecretsClient
	switch scenario {
	case "not_found":
		client = &mockSecretsClient{err: &types.ResourceNotFoundException{Message: aws.String("not found")}}
	case "unreachable":
		client = &mockSecretsClient{err: errors.New("connection refused")}
	case "nil_string":
		client = &mockSecretsClient{secretString: nil}
	default:
		t.Fatalf("unknown scenario: %s", scenario)
	}

	adapter := infra.NewSecretsManagerAdapterWithClient(client, infra.NewSlogLogger())
	infra.MustGetSecret(context.Background(), adapter, "arn:aws:secretsmanager:us-east-1:123:secret:test", infra.NewSlogLogger())
}

func runMustGetSecretSubprocess(t *testing.T, scenario string) (exitCode int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestMustGetSecret_ExitHelper", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_MUST_GET_SECRET_CASE="+scenario)
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("unexpected error running subprocess: %v", err)
	return -1
}

func TestMustGetSecret_Success(t *testing.T) {
	want := "my-secret-value"
	client := &mockSecretsClient{secretString: aws.String(want)}
	adapter := infra.NewSecretsManagerAdapterWithClient(client, infra.NewSlogLogger())

	got := infra.MustGetSecret(context.Background(), adapter, "arn:aws:secretsmanager:us-east-1:123:secret:ok", infra.NewSlogLogger())
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMustGetSecret_NotFound_Exits(t *testing.T) {
	code := runMustGetSecretSubprocess(t, "not_found")
	if code != 1 {
		t.Errorf("expected exit code 1 for ResourceNotFoundException, got %d", code)
	}
}

func TestMustGetSecret_Unreachable_Exits(t *testing.T) {
	code := runMustGetSecretSubprocess(t, "unreachable")
	if code != 1 {
		t.Errorf("expected exit code 1 for unreachable Secrets Manager, got %d", code)
	}
}

func TestMustGetSecret_NilString_Exits(t *testing.T) {
	code := runMustGetSecretSubprocess(t, "nil_string")
	if code != 1 {
		t.Errorf("expected exit code 1 for nil SecretString, got %d", code)
	}
}

func TestMustLoadSecrets_Success(t *testing.T) {
	secrets := map[string]string{
		"arn:aws:secretsmanager:us-east-1:123:secret:a": "val-a",
		"arn:aws:secretsmanager:us-east-1:123:secret:b": "val-b",
	}

	// Build a client that returns different values per ARN.
	client := &multiSecretClient{secrets: secrets}
	adapter := infra.NewSecretsManagerAdapterWithClient(client, infra.NewSlogLogger())

	arns := []string{
		"arn:aws:secretsmanager:us-east-1:123:secret:a",
		"arn:aws:secretsmanager:us-east-1:123:secret:b",
	}
	got := infra.MustLoadSecrets(context.Background(), adapter, arns, infra.NewSlogLogger())

	for _, arn := range arns {
		if got[arn] != secrets[arn] {
			t.Errorf("arn %s: got %q, want %q", arn, got[arn], secrets[arn])
		}
	}
}

func TestMustLoadSecrets_EmptyARNs(t *testing.T) {
	adapter := infra.NewSecretsManagerAdapterWithClient(&mockSecretsClient{}, infra.NewSlogLogger())
	got := infra.MustLoadSecrets(context.Background(), adapter, nil, infra.NewSlogLogger())
	if len(got) != 0 {
		t.Errorf("expected empty map for nil arns, got %v", got)
	}
}

// multiSecretClient returns different secret values keyed by the requested ARN.
type multiSecretClient struct {
	secrets map[string]string
}

func (m *multiSecretClient) GetSecretValue(_ context.Context, params *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	arn := aws.ToString(params.SecretId)
	val, ok := m.secrets[arn]
	if !ok {
		return nil, &types.ResourceNotFoundException{Message: aws.String("not found")}
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(val)}, nil
}
