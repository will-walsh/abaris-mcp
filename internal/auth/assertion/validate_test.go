package assertion_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/will-walsh/abaris-mcp/internal/auth/assertion"
	"github.com/will-walsh/abaris-mcp/internal/infra"
)

// mockKMSValidateClient is a minimal KMSClient for validate tests.
type mockKMSValidateClient struct {
	describeOut *kms.DescribeKeyOutput
	describeErr error
}

func (m *mockKMSValidateClient) Sign(_ context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKMSValidateClient) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return nil, errors.New("not implemented")
}

func (m *mockKMSValidateClient) DescribeKey(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return m.describeOut, m.describeErr
}

func describeOutput(spec types.KeySpec, usage types.KeyUsageType) *kms.DescribeKeyOutput {
	return &kms.DescribeKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeySpec:  spec,
			KeyUsage: usage,
		},
	}
}

// --- Success cases ---

func TestMustValidateKMSKey_RSA2048_SignVerify(t *testing.T) {
	client := &mockKMSValidateClient{
		describeOut: describeOutput(types.KeySpecRsa2048, types.KeyUsageTypeSignVerify),
	}
	// Should not exit — if it does the test process dies, which is itself a failure.
	assertion.MustValidateKMSKey(context.Background(), client, "arn:aws:kms:us-east-1:123:key/test", infra.NewSlogLogger())
}

func TestMustValidateKMSKey_RSA4096_SignVerify(t *testing.T) {
	client := &mockKMSValidateClient{
		describeOut: describeOutput(types.KeySpecRsa4096, types.KeyUsageTypeSignVerify),
	}
	assertion.MustValidateKMSKey(context.Background(), client, "arn:aws:kms:us-east-1:123:key/test", infra.NewSlogLogger())
}

// --- Exit cases via subprocess pattern ---

// TestMustValidateKMSKey_ExitHelper is the subprocess entry point for exit-code tests.
func TestMustValidateKMSKey_ExitHelper(t *testing.T) {
	scenario := os.Getenv("TEST_VALIDATE_KMS_CASE")
	if scenario == "" {
		t.Skip("not a subprocess invocation")
	}

	var client assertion.KMSClient
	switch scenario {
	case "key_not_found":
		client = &mockKMSValidateClient{describeErr: errors.New("key not found")}
	case "wrong_spec":
		client = &mockKMSValidateClient{
			describeOut: describeOutput(types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify),
		}
	case "wrong_usage":
		client = &mockKMSValidateClient{
			describeOut: describeOutput(types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt),
		}
	default:
		t.Fatalf("unknown scenario: %s", scenario)
	}

	assertion.MustValidateKMSKey(context.Background(), client, "arn:aws:kms:us-east-1:123:key/test", infra.NewSlogLogger())
}

func runValidateSubprocess(t *testing.T, scenario string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestMustValidateKMSKey_ExitHelper", "-test.v")
	cmd.Env = append(os.Environ(), "TEST_VALIDATE_KMS_CASE="+scenario)
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

func TestMustValidateKMSKey_KeyNotFound_Exits(t *testing.T) {
	code := runValidateSubprocess(t, "key_not_found")
	if code != 1 {
		t.Errorf("expected exit code 1 for key not found, got %d", code)
	}
}

func TestMustValidateKMSKey_WrongSpec_Exits(t *testing.T) {
	code := runValidateSubprocess(t, "wrong_spec")
	if code != 1 {
		t.Errorf("expected exit code 1 for wrong key spec, got %d", code)
	}
}

func TestMustValidateKMSKey_WrongUsage_Exits(t *testing.T) {
	code := runValidateSubprocess(t, "wrong_usage")
	if code != 1 {
		t.Errorf("expected exit code 1 for wrong key usage, got %d", code)
	}
}
