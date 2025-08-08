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
	publicKeyPath                                     string
	caBundlePath                                      string
	fulcioCABundlePath, fulcioOIDCIssuer, fulcioEmail string
	requireRekor                                      commonFlag.OptionalBool
}

func cosignVerificationFlags() (pflag.FlagSet, *cosignVerificationOptions) {
	opts := cosignVerificationOptions{}
	fs := pflag.FlagSet{}
	fs.StringVar(&opts.publicKeyPath, "public-key", "", "expect a signature signed by `PUBLIC-KEY`")
	fs.StringVar(&opts.caBundlePath, "ca", "", "expect a signature signed by a certificate issued by one of certificates in `CA-BUNDLE`")
	fs.StringVar(&opts.fulcioCABundlePath, "fulcio", "", "expect a signature by a Fulcio-issued certificate, trusting `CA-BUNDLE`")
	fs.StringVar(&opts.fulcioOIDCIssuer, "fulcio-issuer", "", "require a Fulcio-issued certificate to be authenticated by `ISSUER`")
	fs.StringVar(&opts.fulcioEmail, "fulcio-email", "", "require a Fulcio-issued certificate to be issued for `EMAIL`")
	commonFlag.OptionalBoolFlag(&fs, &opts.requireRekor, "require-rekor", "require a Rekor SET")
	return fs, &opts
}

func countBools(bools ...bool) int {
	res := 0
	for _, b := range bools {
		if b {
			res++
		}
	}
	return res
}

func (opts *cosignVerificationOptions) runVerification(unverifiedManifestDigest digest.Digest, unverifiedSignature unverifiedSignatureData, stdout io.Writer) error {
	if countBools(opts.publicKeyPath != "", opts.caBundlePath != "", opts.fulcioCABundlePath != "") != 1 {
		return errors.New("Exactly one of --public-key, --ca and --fulcio can be used")
	}
	if opts.fulcioCABundlePath != "" && opts.fulcioOIDCIssuer == "" {
		return errors.New("--fulcio-issuer must be set with --fulcio")
	}
	if opts.fulcioCABundlePath != "" && opts.fulcioEmail == "" {
		return errors.New("--fulcio-email must be set with --fulcio")
	}

	// --- Load the trust policy
	// FIXME? Support RFC3161 timestamps in addition to (instead of?) Rekor.

	var publicKey crypto.PublicKey // = nil
	var caCertificateBundle *x509.CertPool
	if opts.publicKeyPath != "" {
		// github.com/sigstore/cosign/pkg/signature.PublicKeyFromKeyRef(ctx, keyPath) =
		// github.com/sigstore/cosign/pkg/signature.PublicKeyFromKeyRefWithHashAlgo(ctx, keyPath, crypto.SHA256) includes support for k8s://, pkcs11:, gitlab (not even a colon!)
		// github.com/sigstore/cosign/pkg/signature.VerifierForKeyRef(ctx, keyPath, crypto.SHA256) includes support for registered KMSes (at least awskms://, azurekms://, gcpkms://, hashivault://)
		publicKeyPEM, err := os.ReadFile(opts.publicKeyPath)
		if err != nil {
			return fmt.Errorf("Error reading public key from %s: %w", opts.publicKeyPath, err)
		}
		publicKey, err = cryptoutils.UnmarshalPEMToPublicKey(publicKeyPEM)
		if err != nil {
			return fmt.Errorf("Error parsing public key %s: %w", opts.publicKeyPath, err)
		}
		// FIXME? Support specifying a public key using a certificate instead?
	}
	if opts.caBundlePath != "" {
		caCertificateBundle = x509.NewCertPool()
		caCertificateBundlePEM, err := os.ReadFile(opts.caBundlePath)
		if err != nil {
			return fmt.Errorf("Error reading CA certificates from %s: %w", opts.caBundlePath, err)
		}
		if !caCertificateBundle.AppendCertsFromPEM(caCertificateBundlePEM) {
			return fmt.Errorf("Error loading CA certificates from %s", opts.caBundlePath)
		}
	}
	if opts.fulcioCABundlePath != "" {
		// This is ACTUALLY almost the same thing as caBundlePath, but we REQUIRE --fulcio-issuer and --fulcio-email, otherwise there’s no point.
		// FIXME: Do we eventually want to relax that? Team members signing using their own email might be a thing — but then what? A list?

		// Cosign internally uses TUF to obtain the CA certificates. We don’t want that complexity.
		caCertificateBundle = x509.NewCertPool()
		fulcioCABundlePEM, err := os.ReadFile(opts.fulcioCABundlePath)
		if err != nil {
			return fmt.Errorf("Error reading CA certificates from %s: %w", opts.fulcioCABundlePath, err)
		}
		if !caCertificateBundle.AppendCertsFromPEM([]byte(fulcioCABundlePEM)) {
			return fmt.Errorf("Error loading CA certificates from %s", opts.fulcioCABundlePath)
		}
	}
	requireRekor := opts.requireRekor.Value()

	// --- Set up the trust policy
	var verifier signature.Verifier // = nil
	if publicKey != nil {
		v, err := signature.LoadVerifier(publicKey, crypto.SHA256) // FIXME: SHA256 is used for digesting payload, make it at least a shared constant
		if err != nil {
			return fmt.Errorf("Error creating verifier for %s: %w", opts.publicKeyPath, err)
		}
		verifier = v

		if true { // This is unnecessary, VerifyImageSignature below does this
			// FIXME: Is the base64 encoding essential or specific to the --output-signature format?
			unverifiedSignatureBytes, err := base64.StdEncoding.DecodeString(string(unverifiedSignature.unverifiedBase64Signature))
			if err != nil {
				return fmt.Errorf("Error parsing signature as base64: %w", err)
			}
			if err := verifier.VerifySignature(bytes.NewReader(unverifiedSignatureBytes), bytes.NewReader(unverifiedSignature.unverifiedPayload)); err != nil {
				return fmt.Errorf("Error verifying raw payload signature: %w", err)
			}
			fmt.Fprintf(stdout, "Raw payload signature verified\n")
		}
	}
	var rekorPubKeys *cosign.TrustedTransparencyLogPubKeys
	if requireRekor {
		// FIXME FIXME: This invokes TUF to get Rekor public keys. We don’t want that complexity.
		// Load keys from file instead.
		pk, err := cosign.GetRekorPubs(context.TODO())
		if err != nil {
			return fmt.Errorf("Error loading Rekor public keys")
		}
		rekorPubKeys = pk
	}

	// --- The actual verification implementation

	// These situations should be made impossible in the config parser
	if verifier == nil && caCertificateBundle == nil {
		return fmt.Errorf("Internal error: attempting to verify a signature with no root of trust")
	}
	if opts.fulcioCABundlePath != "" && (opts.fulcioOIDCIssuer == "" || opts.fulcioEmail == "") {
		return fmt.Errorf("Internal error: attempting to verify a Fulcio signature with insufficient constraints")
	}
	unverifiedManifestHash, err := v1.NewHash(unverifiedManifestDigest.String())
	if err != nil {
		return fmt.Errorf("Error converting manifest digest %s: %w", unverifiedManifestDigest.String(), err)
	}
	// FIXME: Use a higher-level API??
	// WARNING: VerifyImageSignature MODIFIES CheckOpts; it’s not safe to reuse, or call this in parallel.
	checkOpts := &cosign.CheckOpts{
		SigVerifier: verifier,
		RootCerts:   caCertificateBundle,
		// FIXME FIXME: this is very lax in parsing the payload (naive JSON parser, not even format ID verification)
		// FIXME FIXME: this verifies the hash, but not the name, in the payload!!
		ClaimVerifier: cosign.SimpleClaimVerifier,
		RekorPubKeys:  rekorPubKeys,
		// Unlike cosign, we don’t enforce existence of SCTs that prove upload of generated certificates to a transparency log.
		// If requireRekor, that functionality (and more, actually recording the signature, not just the key) is already
		// provided by Rekor itself, so this is clearly redundant.
		//
		// It could possibly make a difference for non-Rekor certificates, e.g. when using a timestamping authority instead of full
		// Rekor. But still, certificate transparency is a mitigation of trust in possibly-rogue CAs, and the primary countermeasure
		// for that should be just not trusting possibly-rogue CAs (like the full public CA ecosystem) in the first place.
		IgnoreSCT: true,
		Identities: []cosign.Identity{
			{Issuer: opts.fulcioOIDCIssuer, Subject: opts.fulcioEmail},
		},
		// FIXME: Do we want to support, at all, the on-line Rekor query?
		Offline:    true,
		IgnoreTlog: !requireRekor,
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
