package main

import (
	"context"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"go.podman.io/image/v5/manifest"
	"go.podman.io/image/v5/pkg/blobinfocache/none"
	"go.podman.io/image/v5/types"
)

const (
	cosignSignatureAnnotationKey   = "dev.cosignproject.cosign/signature"
	cosignCertificateAnnotationKey = "dev.sigstore.cosign/certificate"
	cosignCertificateChainKey      = "dev.sigstore.cosign/chain"
	cosignBundleAnnotationKey      = "dev.sigstore.cosign/bundle"
)

func getSignaturesFromCosignImage(ctx context.Context, src types.ImageSource) ([]unverifiedSignatureData, error) {
	manifestBlob, _, err := src.GetManifest(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	// FIXME? Validate the MIME type first?
	manifest, err := manifest.OCI1FromManifest(manifestBlob)
	if err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	res := []unverifiedSignatureData{}
	for layerIndex, layer := range manifest.Layers {
		unverifiedSignature, err := layerToSignature(ctx, src, layer)
		if err != nil {
			return nil, fmt.Errorf("parsing signature %d/%d: %w", layerIndex+1, len(manifest.Layers), err)
		}
		res = append(res, unverifiedSignature)
	}
	return res, nil
}

// Compare github.com/sigstore/cosign/pkg/oci/internal/signature
func layerToSignature(ctx context.Context, src types.ImageSource, desc imgspecv1.Descriptor) (unverifiedSignatureData, error) {
	unverifiedBase64Signature, ok := desc.Annotations[cosignSignatureAnnotationKey]
	if !ok {
		return unverifiedSignatureData{}, fmt.Errorf("annotation %s not present", cosignSignatureAnnotationKey)
	}
	var unverifiedRekorSET, untrustedEmbeddedCert, untrustedCertChain []byte
	if s, ok := desc.Annotations[cosignBundleAnnotationKey]; ok {
		unverifiedRekorSET = []byte(s)
	}
	if s, ok := desc.Annotations[cosignCertificateAnnotationKey]; ok {
		untrustedEmbeddedCert = []byte(s)
	}
	if s, ok := desc.Annotations[cosignCertificateChainKey]; ok {
		untrustedCertChain = []byte(s)
	}

	stream, _, err := src.GetBlob(ctx, manifest.BlobInfoFromOCI1Descriptor(desc), none.NoCache)
	if err != nil {
		return unverifiedSignatureData{}, fmt.Errorf("opening signature %v: %w", desc.Digest.String(), err)
	}
	defer stream.Close()
	// FIXME: iolimits.ReadAtMost(stream, maxSignatureBodySize)
	unverifiedPayload, err := io.ReadAll(stream)
	if err != nil {
		return unverifiedSignatureData{}, fmt.Errorf("reading signature %v: %w", desc.Digest.String(), err)
	}
	// This is, strictly speaking, unnecessary.
	// We primarily validate the signature against a root of trust, we don’t care so much about
	// the registry’s integrity. But let’s at least attribute corrupt data to the registry.
	computedDigest := digest.FromBytes(unverifiedPayload)
	if computedDigest != desc.Digest {
		return unverifiedSignatureData{}, fmt.Errorf("downloaded signature digest %s does not match expected %s", computedDigest, desc.Digest)
	}

	return unverifiedSignatureData{
		unverifiedPayload:         unverifiedPayload,
		unverifiedBase64Signature: []byte(unverifiedBase64Signature),
		unverifiedRekorSET:        unverifiedRekorSET,
		untrustedEmbeddedCert:     untrustedEmbeddedCert,
		untrustedCertChain:        untrustedCertChain,
	}, nil
}
