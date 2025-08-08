package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	commonFlag "github.com/containers/common/pkg/flag"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/spf13/pflag"
)

type unverifiedSignatureData struct {
	unverifiedPayload, unverifiedBase64Signature                  []byte
	unverifiedRekorSET, untrustedEmbeddedCert, untrustedCertChain []byte
}

// Digest returns the Hash of the compressed layer.
func (sc unverifiedSignatureData) Digest() (v1.Hash, error) {
	panic("not implemented") // TODO: Implement
}

// DiffID returns the Hash of the uncompressed layer.
func (sc unverifiedSignatureData) DiffID() (v1.Hash, error) {
	panic("not implemented") // TODO: Implement
}

// Compressed returns an io.ReadCloser for the compressed layer contents.
func (sc unverifiedSignatureData) Compressed() (io.ReadCloser, error) {
	panic("not implemented") // TODO: Implement
}

// Uncompressed returns an io.ReadCloser for the uncompressed layer contents.
func (sc unverifiedSignatureData) Uncompressed() (io.ReadCloser, error) {
	panic("not implemented") // TODO: Implement
}

// Size returns the compressed size of the Layer.
func (sc unverifiedSignatureData) Size() (int64, error) {
	panic("not implemented") // TODO: Implement
}

// MediaType returns the media type of the Layer.
func (sc unverifiedSignatureData) MediaType() (types.MediaType, error) {
	panic("not implemented") // TODO: Implement
}

// Annotations returns the annotations associated with this layer.
func (sc unverifiedSignatureData) Annotations() (map[string]string, error) {
	panic("not implemented") // TODO: Implement
}

// Payload fetches the opaque data that is being signed.
// This will always return data when there is no error.
func (sc unverifiedSignatureData) Payload() ([]byte, error) {
	return sc.unverifiedPayload, nil
}

// Signature fetches the raw signature
// of the payload.  This will always return data when
// there is no error.
func (sc unverifiedSignatureData) Signature() ([]byte, error) {
	return base64.StdEncoding.DecodeString(string(sc.unverifiedBase64Signature))
}

// Base64Signature fetches the base64 encoded signature
// of the payload.  This will always return data when
// there is no error.
func (sc unverifiedSignatureData) Base64Signature() (string, error) {
	return string(sc.unverifiedBase64Signature), nil
}

// Cert fetches the optional public key from the key pair that
// was used to sign the payload.
func (sc unverifiedSignatureData) Cert() (*x509.Certificate, error) {
	if sc.untrustedEmbeddedCert == nil {
		return nil, nil
	}

	untrustedEmbbeddedCerts, err := cryptoutils.UnmarshalCertificatesFromPEM(sc.untrustedEmbeddedCert)
	if err != nil {
		return nil, err
	}
	switch len(untrustedEmbbeddedCerts) {
	case 0:
		return nil, errors.New("no certificate found in signature certificate data")
	case 1:
		return untrustedEmbbeddedCerts[0], nil
	default:
		return nil, fmt.Errorf("unexpected multiple certificates present in signature certificate data")
	}
}

// Chain fetches the optional "full certificate chain" rooted
// at a Fulcio CA, the leaf of which was used to sign the
// payload.
func (sc unverifiedSignatureData) Chain() ([]*x509.Certificate, error) {
	if sc.untrustedCertChain == nil {
		return nil, nil
	}

	untrustedCertChain, err := cryptoutils.UnmarshalCertificatesFromPEM(sc.untrustedCertChain)
	if err != nil {
		return nil, err
	}
	return untrustedCertChain, nil
}

// Bundle fetches the optional metadata that records the ephemeral
// Fulcio key in the transparency log.
func (sc unverifiedSignatureData) Bundle() (*bundle.RekorBundle, error) {
	if sc.unverifiedRekorSET == nil {
		return nil, nil
	}
	var v bundle.RekorBundle
	if err := json.Unmarshal(sc.unverifiedRekorSET, &v); err != nil {
		return nil, fmt.Errorf("error parsing Rekor SET: %w", err)
	}
	return &v, nil
}

// RFC3161Timestamp() fetches the optional metadata that records a
// RFC3161 signed timestamp.
func (sc unverifiedSignatureData) RFC3161Timestamp() (*bundle.RFC3161Timestamp, error) {
	panic("not implemented") // TODO: Implement instead / in addition to Rekor
}

type cosignVerificationOptions struct {
	publicKeyPath string
	requireRekor  commonFlag.OptionalBool
}

func cosignVerificationFlags() (pflag.FlagSet, *cosignVerificationOptions) {
	opts := cosignVerificationOptions{}
	fs := pflag.FlagSet{}
	fs.StringVar(&opts.publicKeyPath, "public-key", "", "expect a signature signed by `PUBLIC-KEY`")
	commonFlag.OptionalBoolFlag(&fs, &opts.requireRekor, "require-rekor", "require a Rekor SET")
	return fs, &opts
}

func (opts *cosignVerificationOptions) runVerification(unverifiedManifestDigest digest.Digest, unverifiedSignature unverifiedSignatureData, stdout io.Writer) error {
	if opts.publicKeyPath == "" {
		return errors.New("--public-key must be used")
	}

	// --- Load the trust policy
	// FIXME? Support specifying a public key using a certificate instead?
	// FIXME: Support Fulcio-signed certificates (is there a difference from ordinary certificates?)
	// FIXME? Support RFC3161 timestamps in addition to (instead of?) Rekor.

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
	if !opts.requireRekor.Present() {
		return errors.New("--require-rekor must be specified")
	}
	requireRekor := opts.requireRekor.Value()

	// --- Set up the trust policy
	verifier, err := signature.LoadVerifier(publicKey, crypto.SHA256) // FIXME: SHA256 is used for digesting payload, make it at least a shared constant
	if err != nil {
		return fmt.Errorf("Error creating verifier for %s: %w", opts.publicKeyPath, err)
	}
	var rekorPubKeys *cosign.TrustedTransparencyLogPubKeys
	if requireRekor {
		// FIXME FIXME: This invokes TUF to get a Rekor public key. We don’t want that complexity.
		// Load keys from file instead.
		rekorPubKeys, err = cosign.GetRekorPubs(context.TODO())
		if err != nil {
			return fmt.Errorf("Error loading Rekor public keys")
		}
	}

	// --- The actual verification implementation

	unverifiedSignatureBytes, err := base64.StdEncoding.DecodeString(string(unverifiedSignature.unverifiedBase64Signature))
	if err != nil {
		return fmt.Errorf("Error parsing signature as base64: %w", err)
	}
	if true { // This is unnecessary, VerifyImageSignature below does this
		if err := verifier.VerifySignature(bytes.NewReader(unverifiedSignatureBytes), bytes.NewReader(unverifiedSignature.unverifiedPayload)); err != nil {
			return fmt.Errorf("Error verifying raw payload signature: %w", err)
		}
		fmt.Fprintf(stdout, "Raw payload signature verified\n")
	}
	unverifiedManifestHash, err := v1.NewHash(unverifiedManifestDigest.String())
	if err != nil {
		return fmt.Errorf("Error converting manifest digest %s: %w", unverifiedManifestDigest.String(), err)
	}
	// FIXME: Use a higher-level API??
	// FIXME: Do we want to support, at all, the on-line Rekor query?
	// WARNING: VerifyImageSignature MODIFIES CheckOpts; it’s not safe to reuse, or call this in parallel.
	checkOpts := &cosign.CheckOpts{
		SigVerifier: verifier,
		// FIXME FIXME: this is very lax in parsing the payload (naive JSON parser, not even format ID verification)
		// FIXME FIXME: this verifies the hash, but not the name, in the payload!!
		ClaimVerifier: cosign.SimpleClaimVerifier,
		RekorPubKeys:  rekorPubKeys,
		Offline:       true,
		IgnoreTlog:    !requireRekor,
	}
	bundleVerified, err := cosign.VerifyImageSignature(context.TODO(), unverifiedSignature, unverifiedManifestHash, checkOpts)
	if err != nil {
		return fmt.Errorf("Error verifying signature mid-level: %w", err)
	}
	fmt.Fprintf(stdout, "Mid-level signature verified\n")
	if requireRekor && !bundleVerified {
		return fmt.Errorf("Internal error: Rekor SET verification was requested but did not succeed")
	}

	return nil
}
