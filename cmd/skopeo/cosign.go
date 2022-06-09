package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
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
		Use:   "cosign-standalone-verify PAYLOAD SIGNATURE",
		Short: "Verify a signature using local files",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&verificationFlags)
	return cmd
}

func (opts *cosignStandaloneVerifyOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 2 {
		return errors.New("Usage: skopeo cosign-standalone-verify --public-key ... payload signature")
	}
	payloadPath := args[0]
	signaturePath := args[1]

	// --- Load the verification subject
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

	return opts.verification.runVerification(unverifiedSignature, stdout)
}
