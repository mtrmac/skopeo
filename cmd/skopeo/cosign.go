package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	fulcio "github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauth"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"github.com/spf13/cobra"
	"go.podman.io/image/v5/docker/reference"
	"go.podman.io/image/v5/manifest"
	"go.podman.io/image/v5/pkg/cli"
)

const (
	// defaultFulcioURL is the URL to use on the open Internet.
	// FIXME: This is also available as
	// github.com/sigstore/cosign/cmd/cosign/cli/options.DefaultFulcioConfig, but that is not
	// practical due to the amount of dependencies it adds.
	defaultFulcioURL = "https://fulcio.sigstore.dev"
	// defaultFulcioOIDCIssuerURL is the URL of the OIDC issuer to use with defaultFulcioURL
	// FIXME: This is also available as
	// github.com/sigstore/cosign/cmd/cosign/cli/options.DefaultOIDCIssuerURL, but that is not
	// practical due to the amount of dependencies it adds.
	defaultFulcioOIDCIssuerURL = "https://oauth2.sigstore.dev/auth"
	defaultFulcioOIDCClientID  = "sigstore"
	// FIXME: This is also available as
	// github.com/sigstore/cosign/cmd/cosign/cli/options.DefaultRekorURL, but that is not
	// practical due to the amount of dependencies it adds.
	defaultRekorURL = "https://rekor.sigstore.dev"
)

type cosignStandaloneSignOptions struct {
	global              *globalOptions
	rekorUpload         *cosignRekorUploadOptions
	keyPath             string
	keyPassphrasePath   string
	fulcioURL           string
	fulcioOIDCIssuerURL string
	fulcioOIDCClientID  string
	defaultFulcioConfig bool

	payloadPath          string // Output payload path
	signaturePath        string // Output signature path
	certificatePath      string // Output certificate path
	certificateChainPath string // Output certificate chain path
	rekorSETPath         string
}

func cosignStandaloneSignCmd(global *globalOptions) *cobra.Command {
	rekorUploadFlags, rekorUploadOpts := cosignRekorUploadFlags()
	opts := cosignStandaloneSignOptions{
		global:      global,
		rekorUpload: rekorUploadOpts,
	}
	cmd := &cobra.Command{
		Use:   "cosign-standalone-sign [command options] --key|--fulcio-* ... MANIFEST DOCKER-REFERENCE --payload|-p PAYLOAD --signature|-s SIGNATURE",
		Short: "Create a signature using local files",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&rekorUploadFlags)
	flags.StringVar(&opts.keyPath, "key", "", "sign using private key in `KEY`")
	flags.StringVar(&opts.keyPassphrasePath, "key-passphrase-file", "", "Read a passphrase for --key from `FILE`")
	flags.StringVar(&opts.fulcioURL, "fulcio-url", "", "use Fulcio at `FULCIO-URL` to obtain a short-term certificate")
	flags.StringVar(&opts.fulcioOIDCIssuerURL, "fulcio-oidc-issuer-url", "", "use an OIDC issuer at `OIDC-URL` to authenticate with Fulcio")
	flags.StringVar(&opts.fulcioOIDCClientID, "fulcio-oidc-client-id", "", "use `CLIENT-ID` for the OIDC issuer needed for Fulcio")
	flags.BoolVar(&opts.defaultFulcioConfig, "fulcio-default", false,
		fmt.Sprintf("use Fulcio at the default URL (%s) to obtain a short-term certificate", defaultFulcioURL))
	flags.StringVarP(&opts.signaturePath, "signature", "s", "", "write the signature to `SIGNATURE`")
	flags.StringVarP(&opts.payloadPath, "payload", "p", "", "write the payload to `PAYLOAD`")
	flags.StringVar(&opts.certificatePath, "certificate", "", "write the generated (short-term) certificate to `CERTIFICATE`")
	flags.StringVar(&opts.certificateChainPath, "certificate-chain", "", "write the certificate chain of generated (short-term) certificate to `CERTIFICATE-CHAIN`")
	flags.StringVar(&opts.rekorSETPath, "rekor-set", "", "Create a Rekor SET and write it to `SET-PATH`")
	return cmd
}

func (opts *cosignStandaloneSignOptions) run(args []string, stdout io.Writer) error {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 2 || opts.payloadPath == "" || opts.signaturePath == "" {
		return errors.New("Usage: skopeo standalone-sign manifest docker-reference private-key -p payload -s signature")
	}
	if opts.defaultFulcioConfig {
		if opts.fulcioURL != "" {
			return errors.New("--fulcio-url and --fulcio-default can not be used simultaneously")
		}
		if opts.fulcioOIDCIssuerURL != "" {
			return errors.New("--fulcio-oidc-issuer-url and --fulcio-default can not be used simultaneously")
		}
		opts.fulcioURL = defaultFulcioURL
		opts.fulcioOIDCIssuerURL = defaultFulcioOIDCIssuerURL
		opts.fulcioOIDCClientID = defaultFulcioOIDCClientID
	}
	if opts.keyPath != "" && opts.fulcioURL != "" {
		return errors.New("--key and Fulcio can not be used simultaneously")
	}
	if opts.keyPath == "" {
		if opts.keyPassphrasePath != "" {
			return errors.New("--key-passphrase-file can only be used with --key")
		}
	}
	if opts.fulcioURL == "" {
		if opts.certificatePath != "" {
			return errors.New("--certificate can only be used with Fulcio")
		}
		if opts.certificateChainPath != "" {
			return errors.New("--certificate-chain can only be used with Fulcio")
		}
	}
	if opts.fulcioURL != "" {
		if opts.fulcioOIDCIssuerURL == "" {
			return errors.New("--fulcio-url requires --fulcio-oidc-issuer-url")
		}
		if opts.fulcioOIDCClientID == "" {
			return errors.New("--fulcio-url requires --fulcio-oidc-client-id")
		}
	}
	if opts.rekorSETPath != "" {
		if err := opts.rekorUpload.canonicalizeOptions(); err != nil {
			return err
		}
	}
	manifestPath := args[0]
	dockerReferenceString := args[1]

	// --- Set up the subject to sign
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("Error reading manifest from %s: %w", manifestPath, err)
	}
	dockerReference, err := reference.ParseNormalizedNamed(dockerReferenceString)
	if err != nil {
		return fmt.Errorf("Error parsing docker reference %q: %w", dockerReferenceString, err)
	}

	// --- Set up signing credentials
	var signer signature.Signer
	var generatedCertificate, generatedCertificateChain, signingKeyOrCert []byte
	if opts.keyPath != "" {
		// github.com/sigstore/cosign/pkg/signature.SignerVerifierForKeyRef(ctx, keyRef, pf) includes support for pkcs11:, k8s://, gitlab (not even a colon!),
		// and any other registered KMSes (at least awskms://, azurekms://, gcpkms://, hashivault://).
		privateKeyPEM, err := os.ReadFile(opts.keyPath)
		if err != nil {
			return fmt.Errorf("Error reading private key from %s: %w", opts.keyPath, err)
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
		publicKey, err := signerVerifier.PublicKey()
		if err != nil {
			return fmt.Errorf("Error getting public key from private key: %w", err)
		}
		publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(publicKey)
		if err != nil {
			return fmt.Errorf("Error converting public key to PEM: %w", err)
		}
		signer = signerVerifier
		signingKeyOrCert = publicKeyPEM
		// FIXME: For generated signatures, should we allow attaching an user-specified certificate (+chain?)
	} else if opts.fulcioURL != "" {
		fulcioURL, err := url.Parse(opts.fulcioURL)
		if err != nil {
			return fmt.Errorf("Error parsing Fulcio URL %q: %w", opts.fulcioURL, err)
		}
		fulcioClient := fulcio.NewClient(fulcioURL, fulcio.WithUserAgent(defaultUserAgent))

		privateKey, err := cosign.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("Error generating short-term private key: %w", err)
		}
		keyAlgorithm := "ecdsa" // This is a hard-coded aspect of the cosign.GeneratePrivateKey() API.
		// signature.LoadECDSASignerVerifier , we don’t actually need the verifier
		s, err := signature.LoadECDSASigner(privateKey, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("Error initializing short-term private key: %w", err)
		}
		signer = s

		// --- FIXME: Split this into a separate function. OIDC Authentication
		// UI: At least Fulcio (together with Rekor?) should probably be configurable by pointing at a config file,
		// the minimum set of options (issuer, client ID, possibly secret) is very unwieldy to type.
		// FIXME: Should all of these be configurable?
		fulcioTokenSourceMethod := 2 // FIXME FIXME: Do we want all of this?
		fulcioIDToken := ""          // FIXME: Used for "token" method. FIXME: Make this configurable? Allow automatically loading it, per sigstore/cosign/pkg/providers?
		fulcioOIDCClientSecret := "" // FIXME: Where does this come from?
		var tokenGetter oauthflow.TokenGetter
		switch fulcioTokenSourceMethod {
		case 0: // FIXME: "device"
			// urn:ietf:params:oauth:grant-type:device_code = RFC 8628
			// WARNING: This gives oauth2.sigstore.dev access
			// the users’ approved credentials, and makes it a trusted party.
			// Are there third-party implementations? Do we even need to support this flow?
			// FIXME: tokenGetter.MessagePrinter hard-codes stdout (could be overridden)
			tokenGetter = oauthflow.NewDeviceFlowTokenGetterForIssuer(opts.fulcioOIDCIssuerURL)
		case 1: // FIXME: "token"
			// This essentially just returns (and parses) the fulcioIDToken value
			tokenGetter = &oauthflow.StaticTokenGetter{RawToken: fulcioIDToken}
		case 2: // FIXME: "normal"
			// NOTE: This listens on localhost, and expects a browser to connect there on auth success; that is unusable from inside a container.
			// If launching the browser fails, it instructs the user to manually open a browser, and then enter a code.
			// This is intended to match oauthflow.DefaultIDTokenGetter, overriding only input/output
			tokenGetter = &oauthflow.InteractiveIDTokenGetter{
				HTMLPage: oauth.InteractiveSuccessHTML,
				Input:    os.Stdin, // Eventually we want to make this a parameter to run() to allow testing
				Output:   stdout,
			}
		default:
			return errors.New("Internal error: unknown token source") // FIXME: make this unreachable
		}
		// NOTE: opts.fulcioOIDCIssuerURL, opts.fulcioOIDCClientID, fulcioOIDCClientSecret are actually not used in the StaticTokenGetter case.
		oidcIDToken, err := oauthflow.OIDConnect(opts.fulcioOIDCIssuerURL, opts.fulcioOIDCClientID, fulcioOIDCClientSecret, "", tokenGetter)
		if err != nil {
			return fmt.Errorf("Error authenticating with OIDC: %w", err)
		}

		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			return fmt.Errorf("Error converting public key to ASN.1: %w", err)
		}
		// Sign the email address as part of the request
		h := sha256.Sum256([]byte(oidcIDToken.Subject))
		keyOwnershipProof, err := ecdsa.SignASN1(rand.Reader, privateKey, h[:])
		if err != nil {
			return fmt.Errorf("Error signing key ownership proof: %w", err)
		}

		// Note that unlike most OAuth2 uses, this passes the ID token, not an access token.
		// This is only secure if every Fulcio server has an individual client ID value
		// = fulcioOIDCClientID, distinct from other Fulcio servers,
		// that is embedded into the ID token’s "aud" field.
		resp, err := fulcioClient.SigningCert(fulcio.CertificateRequest{
			PublicKey: fulcio.Key{
				Content:   publicKeyBytes,
				Algorithm: keyAlgorithm,
			},
			SignedEmailAddress: keyOwnershipProof,
		}, oidcIDToken.RawString)

		if err != nil {
			return fmt.Errorf("Error obtaining certificate: %w", err)
		}
		generatedCertificate = resp.CertPEM
		generatedCertificateChain = resp.ChainPEM
		// Cosign goes through an unmarshal/marshal roundtrip for Fulcio-generated certificates, let’s not do that.
		signingKeyOrCert = resp.CertPEM
		// FIXME FIXME: "github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioverifier".NewSigner:
		// This SCT verifies that Fulcio has uploaded the generated certificate to a transparency log of some kind.
		// Cosign names the option not to verify the SCT as "insecure-skip-verify", documents it as
		// “this should only be used for testing”, but… why???
		// As the _signer_, we don’t really care whether the certificate has been published, as long as consumers accept it.
		// If there is any requirement for transparency, it’s the _consumers_ who need to be enforcing that, and AFAICT
		// they are not: This SCT is not even included in the signature.
		// The consumers, if they care about transparency at all, verify that Rekor has a record of the signature + payload hash
		// (neither of which actually identifies the signed content or the signing identity??!), so… what’s the point?!
		_ = resp.SCT
	} else { // This should have been prevented in the CLI options check
		return errors.New("Internal error: no signing credentials available")
	}

	// --- The actual signing implementation
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
	signatureBytes, err := signer.SignMessage(bytes.NewReader(payloadBytes))
	if err != nil {
		return fmt.Errorf("Error creating signature: %w", err)
	}
	base64Signature := base64.StdEncoding.EncodeToString(signatureBytes)

	var rekorSETBytes []byte
	if opts.rekorSETPath != "" {
		set, err := opts.rekorUpload.uploadEntry(ctx, signingKeyOrCert, signatureBytes, payloadBytes)
		if err != nil {
			return err
		}
		rekorSETBytes = set
	}

	// --- Write the signing outcome
	if err := os.WriteFile(opts.payloadPath, payloadBytes, 0644); err != nil {
		return fmt.Errorf("Error writing payload to %s: %w", opts.payloadPath, err)
	}
	if err := os.WriteFile(opts.signaturePath, []byte(base64Signature), 0600); err != nil {
		return fmt.Errorf("Error writing signature to %s: %w", opts.signaturePath, err)
	}
	if opts.certificatePath != "" {
		if generatedCertificate == nil { // This should have been prevented in the CLI options check
			return errors.New("Internal error: --certificate was accepted but no certificate was created")
		}
		if err := os.WriteFile(opts.certificatePath, []byte(generatedCertificate), 0644); err != nil {
			return fmt.Errorf("Error writing certificate to %s: %w", opts.certificatePath, err)
		}
	}
	if opts.certificateChainPath != "" {
		if generatedCertificateChain == nil { // This should have been prevented in the CLI options check
			return errors.New("Internal error: --certificate-chain was accepted but no certificate was created")
		}
		if err := os.WriteFile(opts.certificateChainPath, []byte(generatedCertificateChain), 0644); err != nil {
			return fmt.Errorf("Error writing certificate chain to %s: %w", opts.certificateChainPath, err)
		}
	}
	if opts.rekorSETPath != "" {
		if rekorSETBytes == nil {
			return errors.New("Internal error: --rekor-set was accepted but no SET was created")
		}
		if err := os.WriteFile(opts.rekorSETPath, rekorSETBytes, 0644); err != nil {
			return fmt.Errorf("Error writing Rekor SET to %s: %w", opts.rekorSETPath, err)
		}
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

type cosignStandaloneRekorUploadOptions struct {
	global  *globalOptions
	upload  *cosignRekorUploadOptions
	setPath string
}

func cosignRekorUpload(global *globalOptions) *cobra.Command {
	uploadFlags, uploadOpts := cosignRekorUploadFlags()
	opts := cosignStandaloneRekorUploadOptions{
		global: global,
		upload: uploadOpts,
	}
	cmd := &cobra.Command{
		Use:   "cosign-rekor-upload KEY-OR-CERT SIGNATURE PAYLOAD -o SET",
		Short: "",
		RunE:  commandAction(opts.run),
	}
	adjustUsage(cmd)
	flags := cmd.Flags()
	flags.AddFlagSet(&uploadFlags)
	flags.StringVarP(&opts.setPath, "output", "o", "", "Write the SET to `SET-PATH`")
	return cmd
}

func (opts *cosignStandaloneRekorUploadOptions) run(args []string, stdout io.Writer) error {
	ctx, cancel := opts.global.commandTimeoutContext()
	defer cancel()

	if len(args) != 3 || opts.setPath == "" {
		return errors.New("Usage: skopeo cosign-rekor-upload key-or-cert signature payload -o set")
	}
	if err := opts.upload.canonicalizeOptions(); err != nil {
		return err
	}
	keyOrCertPath := args[0]
	signaturePath := args[1]
	payloadPath := args[2]

	// -- Set up the subject to upload
	keyOrCertBytes, err := os.ReadFile(keyOrCertPath)
	if err != nil {
		return fmt.Errorf("Error reading key-or-cert from %s: %w", keyOrCertPath, err)
	}
	base64Signature, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("Error reading signature from %s: %w", signaturePath, err)
	}
	payloadBytes, err := os.ReadFile(payloadPath)
	if err != nil {
		return fmt.Errorf("Error reading payload from %s: %w", payloadPath, err)
	}

	// Prepare contents
	signatureBytes, err := base64.StdEncoding.DecodeString(string(base64Signature)) // Ultimately this shouldn’t be necessary.
	if err != nil {
		return fmt.Errorf("Error decoding signature: %w", err)
	}
	// Cosign goes through an unmarshal/marshal roundtrip for Fulcio-generated certificates, let’s not.
	// NOTE: For a caller-provided private key, we might need to extract the public key and marshal here, for convenience.

	rekorSET, err := opts.upload.uploadEntry(ctx, keyOrCertBytes, signatureBytes, payloadBytes)
	if err != nil {
		return err
	}
	if err := os.WriteFile(opts.setPath, []byte(rekorSET), 0644); err != nil {
		return fmt.Errorf("Error writing SET to %s: %w", opts.setPath, err)
	}
	return nil
}
