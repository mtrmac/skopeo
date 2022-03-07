package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/spf13/cobra"
	"go.podman.io/image/v5/docker/reference"
	"go.podman.io/image/v5/manifest"
	"go.podman.io/image/v5/pkg/cli"
)

type cosignStandaloneSignOptions struct {
	keyPassphrasePath string

	payloadPath   string // Output payload path
	signaturePath string // Output signature path
}

func cosignStandaloneSignCmd() *cobra.Command {
	opts := cosignStandaloneSignOptions{}
	cmd := &cobra.Command{
		Use:   "cosign-standalone-sign [command options] MANIFEST DOCKER-REFERENCE PRIVATE-KEY --payload|-p PAYLOAD --signature|-s SIGNATURE",
		Short: "Create a signature using local files",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.StringVar(&opts.keyPassphrasePath, "key-passphrase-file", "", "Read a passphrase for --key from `FILE`")
	flags.StringVarP(&opts.signaturePath, "signature", "s", "", "output the signature to `SIGNATURE`")
	flags.StringVarP(&opts.payloadPath, "payload", "p", "", "output the payload to `PAYLOAD`")
	return cmd
}

func (opts *cosignStandaloneSignOptions) run(args []string, stdout io.Writer) error {
	if len(args) != 3 || opts.payloadPath == "" || opts.signaturePath == "" {
		return errors.New("Usage: skopeo standalone-sign manifest docker-reference private-key -p payload -s signature")
	}
	manifestPath := args[0]
	dockerReferenceString := args[1]
	keyPath := args[2]

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading manifest from %s: %w", manifestPath, err)
	}
	dockerReference, err := reference.ParseNormalizedNamed(dockerReferenceString)
	if err != nil {
		return fmt.Errorf("Error parsing docker reference %q: %w", dockerReferenceString, err)
	}

	// FIXME: Support keyless signing

	// github.com/sigstore/cosign/pkg/signature.SignerVerifierForKeyRef(ctx, keyRef, pf) includes support for pkcs11:, k8s://, gitlab (not even a colon!),
	// and any other registered KMSes (at least awskms://, azurekms://, gcpkms://, hashivault://).
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("Error reading private key from %s: %w", keyPath, err)
	}
	var passphrase []byte
	if opts.keyPassphrasePath != "" {
		// Use the same format as simple signing’s --sign-passphrase-file .
		// It’s not the only obvious choice; at least the consistency is valuable.
		p, err := cli.ReadPassphraseFile(opts.keyPassphrasePath)
		if err != nil {
			return err
		}
		passphrase = []byte(p)
	} else {
		p, err := cosign.GetPassFromTerm(false)
		if err != nil {
			return fmt.Errorf("Error prompting for a passphrase: %w", err)
		}
		passphrase = p
	}

	signerVerifier, err := cosign.LoadPrivateKey(privateKeyPEM, passphrase)
	if err != nil {
		return fmt.Errorf("Error initializing private key: %w", err)
	}

	manifestDigest, err := manifest.Digest(manifestBytes)
	if err != nil {
		return fmt.Errorf("Error computing manifest digest: %w", err)
	}

	// FIXME FIXME: This generates an identity with only a repo name, not a tag
	repoRef, err := name.NewRepository(dockerReference.Name(), name.StrictValidation)
	if err != nil {
		return fmt.Errorf("Error converting repository name %q: %w", dockerReference.Name(), err)
	}
	digestedRef := repoRef.Digest(manifestDigest.String())
	payloadBytes, err := payload.Cosign{
		Image:       digestedRef,
		Annotations: nil,
	}.MarshalJSON()
	if err != nil {
		return fmt.Errorf("Error creating payload to sign: %w", err)
	}

	// github.com/sigstore/cosign/internal/pkg/cosign.payloadSigner uses signatureoptions.WithContext(),
	// which seems to be not used by anything. So we don’t bother.
	signatureBytes, err := signerVerifier.SignMessage(bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("Error creating signature: %w", err)
	}
	base64Signature := base64.StdEncoding.EncodeToString(signatureBytes)

	if err := os.WriteFile(opts.payloadPath, payloadBytes, 0644); err != nil {
		return fmt.Errorf("Error writing payload to %s: %w", opts.payloadPath, err)
	}
	if err := os.WriteFile(opts.signaturePath, []byte(base64Signature), 0600); err != nil {
		return fmt.Errorf("Error writing signature to %s: %w", opts.signaturePath, err)
	}
	return nil
}

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
