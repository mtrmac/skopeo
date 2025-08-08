package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/containers/image/v5/manifest"
	"github.com/spf13/cobra"
)

type cosignStandaloneVerifyOptions struct {
	verification     *cosignVerificationOptions
	rekorSETpath     string
	embeddedCertPath string
	certChainPath    string
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
	flags.StringVar(&opts.rekorSETpath, "rekor-set", "", "validate a SET from `SET-PATH`")
	flags.StringVar(&opts.embeddedCertPath, "embedded-cert", "", "`CERTIFICATE` is a part of the signature")
	flags.StringVar(&opts.certChainPath, "cert-chain", "", "`CERT-CHAIN` can be used to validate the certificate")
	return cmd
}

func (opts *cosignStandaloneVerifyOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 3 {
		return errors.New("Usage: skopeo cosign-standalone-verify --public-key|--ca ...  manifest payload signature")
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
	var unverifiedRekorSET []byte = nil
	if opts.rekorSETpath != "" {
		unverifiedRekorSET, err = os.ReadFile(opts.rekorSETpath)
		if err != nil {
			return fmt.Errorf("Error reading Rekor SET from %s: %w", opts.rekorSETpath, err)
		}
	}
	var untrustedEmbeddedCert []byte = nil
	if opts.embeddedCertPath != "" {
		untrustedEmbeddedCert, err = os.ReadFile(opts.embeddedCertPath)
		if err != nil {
			return fmt.Errorf("Error reading embedded certificate from %s: %w", opts.embeddedCertPath, err)
		}
	}
	var untrustedCertChain []byte = nil
	if opts.certChainPath != "" {
		untrustedCertChain, err = os.ReadFile(opts.certChainPath)
		if err != nil {
			return fmt.Errorf("Error reading certificate chain from %s: %w", opts.certChainPath, err)
		}
	}

	// --- Set up the verification subject
	unverifiedSignature := unverifiedSignatureData{
		unverifiedPayload:         unverifiedPayload,
		unverifiedBase64Signature: unverifiedBase64Signature,
		unverifiedRekorSET:        unverifiedRekorSET,
		untrustedEmbeddedCert:     untrustedEmbeddedCert,
		untrustedCertChain:        untrustedCertChain,
	}
	unverifiedManifestDigest, err := manifest.Digest(unverifiedManifest)
	if err != nil {
		return fmt.Errorf("Error computing manifest digest: %w", err)
	}

	return opts.verification.runVerification(unverifiedManifestDigest, unverifiedSignature, stdout)
}

type cosignImageVerifyOptions struct {
	global       *globalOptions
	image        *imageOptions
	verification *cosignVerificationOptions
}

func cosignImageVerifyCmd(global *globalOptions) *cobra.Command {
	sharedFlags, sharedOpts := sharedImageFlags()
	imageFlags, imageOpts := imageFlags(global, sharedOpts, nil, "", "")
	verificationFlags, verificationOpts := cosignVerificationFlags()
	opts := cosignImageVerifyOptions{
		global:       global,
		image:        imageOpts,
		verification: verificationOpts,
	}
	// FIXME: Match the payload vs. the image (use the manifest.MatchesDigest)
	cmd := &cobra.Command{
		Use:   "cosign-image-verify MANIFEST IMAGE-NAME",
		Short: "Verify a signature using local files",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&sharedFlags)
	flags.AddFlagSet(&imageFlags)
	flags.AddFlagSet(&verificationFlags)
	return cmd
}

func (opts *cosignImageVerifyOptions) run(args []string, stdout io.Writer) (retErr error) {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 2 {
		return errors.New("Usage: skopeo cosign-image-verify --public-key|--ca ...  manifest image-name")
	}
	manifestPath := args[0]
	imageName := args[1]

	// --- Load the verification subject
	unverifiedManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading manifest from %s: %v", manifestPath, err)
	}
	unverifiedManifestDigest, err := manifest.Digest(unverifiedManifest)
	if err != nil {
		return fmt.Errorf("Error computing manifest digest: %w", err)
	}
	src, err := parseImageSource(ctx, opts.image, imageName)
	if err != nil {
		return fmt.Errorf("Error parsing image name %q: %w", imageName, err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			retErr = fmt.Errorf("(could not close image: %v): %w", err, retErr)
		}
	}()

	unverifiedSignatures, err := getSignaturesFromCosignImage(ctx, src)
	if err != nil {
		return fmt.Errorf("Error reading signatures: %w", err)
	}

	fmt.Fprintf(stdout, "=== %d signatures loaded\n", len(unverifiedSignatures))
	failedSigs := 0
	for i, unverifiedSignature := range unverifiedSignatures {
		fmt.Fprintf(stdout, "=== VERIFYING signature %d/%d\n", i+1, len(unverifiedSignatures))
		err := opts.verification.runVerification(unverifiedManifestDigest, unverifiedSignature, stdout)
		if err == nil {
			fmt.Fprintf(stdout, "... Overall: Succeeded\n")
		} else {
			fmt.Fprintf(stdout, "... Overall: FAILED: %v\n", err)
			failedSigs++
		}
	}
	if failedSigs != 0 {
		// Just to make VERY sure this WIP code isn’t copy&pasted and failures end up being ignored
		return fmt.Errorf("%d/%d signatures failed", failedSigs, len(unverifiedSignatures))
	}
	return nil
}
