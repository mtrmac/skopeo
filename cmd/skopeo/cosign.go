package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"go.podman.io/image/v5/manifest"
)

type cosignStandaloneVerifyOptions struct {
	verification *cosignVerificationOptions
}

func cosignStandaloneVerifyCmd() *cobra.Command {
	verificationFlags, verificationOpts := cosignVerificationFlags()
	opts := cosignStandaloneVerifyOptions{
		verification: verificationOpts,
	}
	// FIXME: Match the payload vs. the image (use the manifest.MatchesDigest)
	cmd := &cobra.Command{
		Use:   "cosign-standalone-verify MANIFEST PAYLOAD SIGNATURE",
		Short: "Verify a signature using local files",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&verificationFlags)
	return cmd
}

func (opts *cosignStandaloneVerifyOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 3 {
		return errors.New("Usage: skopeo cosign-standalone-verify --public-key ... manifest payload signature")
	}
	manifestPath := args[0]
	payloadPath := args[1]
	signaturePath := args[2]

	// --- Load the verification subject
	unverifiedManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading manifest from %s: %v", manifestPath, err)
	}
	unverifiedPayload, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("Error reading payload from %s: %w", payloadPath, err)
	}
	unverifiedBase64Signature, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("Error reading signature from %s: %w", signaturePath, err)
	}

	// --- Set up the verification subject
	unverifiedSignature := unverifiedSignatureData{
		unverifiedPayload:         unverifiedPayload,
		unverifiedBase64Signature: unverifiedBase64Signature,
	}
	unverifiedManifestDigest, err := manifest.Digest(unverifiedManifest)
	if err != nil {
		return fmt.Errorf("Error computing manifest digest: %w", err)
	}

	return opts.verification.runVerification(unverifiedManifestDigest, unverifiedSignature, stdout)
}
