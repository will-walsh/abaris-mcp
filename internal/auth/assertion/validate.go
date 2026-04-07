package assertion

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/will-walsh/abaris-mcp/internal/domain"
)

// validKeySpecs are the RSA key specs accepted for JWT signing.
var validKeySpecs = map[types.KeySpec]bool{
	types.KeySpecRsa2048: true,
	types.KeySpecRsa4096: true,
}

// MustValidateKMSKey calls kms:DescribeKey to verify the key exists, has an
// accepted KeySpec (RSA_2048 or RSA_4096), and has KeyUsage SIGN_VERIFY.
// On any failure it logs at ERROR and calls os.Exit(1).
func MustValidateKMSKey(ctx context.Context, client KMSClient, keyARN string, logger domain.Logger) {
	out, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyARN),
	})
	if err != nil {
		logger.Error("KMS key validation failed: unable to describe key", "key_arn", keyARN, "error", err)
		os.Exit(1)
	}

	meta := out.KeyMetadata
	if meta == nil {
		logger.Error("KMS key validation failed: no key metadata returned", "key_arn", keyARN)
		os.Exit(1)
	}

	if !validKeySpecs[meta.KeySpec] {
		logger.Error("KMS key has unsupported key spec", "key_arn", keyARN, "key_spec", string(meta.KeySpec))
		os.Exit(1)
	}

	if meta.KeyUsage != types.KeyUsageTypeSignVerify {
		logger.Error("KMS key has unsupported key usage", "key_arn", keyARN, "key_usage", string(meta.KeyUsage))
		os.Exit(1)
	}
}
