package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"go.podman.io/image/v5/image"
	"go.podman.io/image/v5/signature"
)

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

	if len(args) != 1 {
		return errors.New("Usage: skopeo cosign-image-verify --public-key|--ca ...  image-name")
	}
	imageName := args[0]

	// Set up policy
	o := []signature.PRSigstoreSignedOption{
		signature.PRSigstoreSignedWithSignedIdentity(signature.NewPRMMatchRepository()),
	}
	if opts.verification.publicKeyPath != "" {
		o = append(o, signature.PRSigstoreSignedWithKeyPath(opts.verification.publicKeyPath))
	}
	// opts.caBundlePath unsupported
	if opts.verification.fulcioCABundlePath != "" {
		fo := []signature.PRSigstoreSignedFulcioOption{
			signature.PRSigstoreSignedFulcioWithCAPath(opts.verification.fulcioCABundlePath),
		}
		if opts.verification.fulcioOIDCIssuer != "" {
			fo = append(fo, signature.PRSigstoreSignedFulcioWithOIDCIssuer(opts.verification.fulcioOIDCIssuer))
		}
		if opts.verification.fulcioEmail != "" {
			fo = append(fo, signature.PRSigstoreSignedFulcioWithSubjectEmail(opts.verification.fulcioEmail))
		}
		fulcio, err := signature.NewPRSigstoreSignedFulcio(fo...)
		if err != nil {
			return fmt.Errorf("Error setting up Fulcio policy entry: %w", err)
		}
		o = append(o, signature.PRSigstoreSignedWithFulcio(fulcio))
	}
	if opts.verification.rekorKeyPath != "" {
		o = append(o, signature.PRSigstoreSignedWithRekorPublicKeyPath(opts.verification.rekorKeyPath))
	}
	pr, err := signature.NewPRSigstoreSigned(o...)
	if err != nil {
		return fmt.Errorf("Error setting up sigstore policy entry: %w", err)
	}
	policy := signature.Policy{Default: signature.PolicyRequirements{pr}}

	context, err := signature.NewPolicyContext(&policy)
	if err != nil {
		return fmt.Errorf("Error creating policy context: %w", err)
	}
	defer context.Destroy()

	// --- Load the verification subject
	src, err := parseImageSource(ctx, opts.image, imageName)
	if err != nil {
		return fmt.Errorf("Error parsing image name %q: %w", imageName, err)
	}
	defer func() {
		if err := src.Close(); err != nil {
			retErr = fmt.Errorf("(could not close image: %v): %w", err, retErr)
		}
	}()
	unparsedToplevel := image.UnparsedInstance(src, nil)

	allowed, err := context.IsRunningImageAllowed(ctx, unparsedToplevel)
	if err != nil {
		fmt.Fprintf(stdout, "... Overall: FAILED: %v\n", err)
		return err
	}
	if !allowed {
		return fmt.Errorf("Internal inconsistency: !allowed but no error")
	}
	fmt.Fprintf(stdout, "... Overall: Succeeded\n")
	return nil
}
