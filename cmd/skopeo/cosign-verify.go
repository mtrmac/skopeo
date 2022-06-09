package main

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/pflag"
)

type unverifiedSignatureData struct {
	unverifiedPayload, unverifiedBase64Signature []byte
}

type cosignVerificationOptions struct {
	publicKeyPath string
}

func cosignVerificationFlags() (pflag.FlagSet, *cosignVerificationOptions) {
	opts := cosignVerificationOptions{}
	fs := pflag.FlagSet{}
	fs.StringVar(&opts.publicKeyPath, "public-key", "", "expect a signature signed by `PUBLIC-KEY`")
	return fs, &opts
}

func (opts *cosignVerificationOptions) runVerification(unverifiedSignature unverifiedSignatureData, stdout io.Writer) error {
	if opts.publicKeyPath == "" {
		return errors.New("--public-key must be used")
	}

	// --- Load the trust policy
	// github.com/sigstore/cosign/pkg/signature.PublicKeyFromKeyRef(ctx, keyPath) =
	// github.com/sigstore/cosign/pkg/signature.PublicKeyFromKeyRefWithHashAlgo(ctx, keyPath, crypto.SHA256) includes support for k8s://, pkcs11:, gitlab (not even a colon!)
	// github.com/sigstore/cosign/pkg/signature.VerifierForKeyRef(ctx, keyPath, crypto.SHA256) includes support for registered KMSes (at least awskms://, azurekms://, gcpkms://, hashivault://)
	publicKeyPEM, err := os.ReadFile(opts.publicKeyPath)
	if err != nil {
		return fmt.Errorf("Error reading public key from %s: %w", opts.publicKeyPath, err)
	}
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("Error parsing public key %s: %w", opts.publicKeyPath, err)
	}

	// --- Set up the trust policy
	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256) // FIXME: SHA256 is used for digesting payload, make it at least a shared constant
	if err != nil {
		return fmt.Errorf("Error creating verifier for %s: %w", opts.publicKeyPath, err)
	}

	// --- The actual verification implementation

	unverifiedSignatureBytes, err := base64.StdEncoding.DecodeString(string(unverifiedSignature.unverifiedBase64Signature))
	if err != nil {
		return fmt.Errorf("Error parsing signature as base64: %w", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(unverifiedSignatureBytes), bytes.NewReader(unverifiedSignature.unverifiedPayload)); err != nil {
		return fmt.Errorf("Error verifying signature: %w", err)
	}
	fmt.Fprintf(stdout, "Signature verified\n")

	return nil
}
