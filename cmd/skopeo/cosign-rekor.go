package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/spf13/pflag"
)

type cosignRekorUploadOptions struct {
	rekorURL           string
	defaultRekorConfig bool
}

func cosignRekorUploadFlags() (pflag.FlagSet, *cosignRekorUploadOptions) {
	opts := cosignRekorUploadOptions{}
	fs := pflag.FlagSet{}
	fs.StringVar(&opts.rekorURL, "rekor-url", "", "Upload to Rekor at `REKOR-URL`")
	fs.BoolVar(&opts.defaultRekorConfig, "rekor-default", false, fmt.Sprintf("Upload to Rekor at the default URL (%s)", defaultRekorURL))
	return fs, &opts
}

func rekorUpload(ctx context.Context, rekorURL string, proposedEntry models.ProposedEntry) (models.LogEntry, error) {
	rekorClient, err := rekor.GetRekorClient(rekorURL)
	if err != nil {
		return nil, fmt.Errorf("Error creating Rekor client: %w", err)
	}
	params := entries.NewCreateLogEntryParamsWithContext(ctx)
	params.SetProposedEntry(proposedEntry)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		// In ordinary operation, we should not get duplicate entries, because our payload contains a timestamp,
		// so it is supposed to be unique; and the default key format, ECDSA p256, also contains a nonce.
		// But conflicts can fairly easily happen during debugging and experimentation, so it pays to handle this.
		var conflictErr *entries.CreateLogEntryConflict
		if errors.As(err, &conflictErr) && conflictErr.Location != "" {
			location := conflictErr.Location.String()
			// We might be able to just GET the returned Location, but let’s use the generated API client.
			// OTOH that requires us to hard-code the URI structure…
			uuidDelimiter := strings.LastIndexByte(location, '/')
			if uuidDelimiter != -1 { // Otherwise the URI is unexpected, and fall through to the bottom
				uuid := location[uuidDelimiter+1:]
				params2 := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
				params2.SetEntryUUID(uuid)
				resp2, err := rekorClient.Entries.GetLogEntryByUUID(params2)
				if err != nil {
					return nil, fmt.Errorf("Error re-loading previously-created log entry with UUID %s: %w", uuid, err)
				}
				return resp2.GetPayload(), nil
			}
		}
		return nil, fmt.Errorf("Error uploading a log entry: %w", err)
	}
	return resp.GetPayload(), nil
}

func (opts *cosignRekorUploadOptions) uploadEntry(ctx context.Context, keyOrCertBytes []byte, signatureBytes []byte, payloadBytes []byte) ([]byte, error) {
	if opts.defaultRekorConfig {
		if opts.rekorURL != "" {
			return nil, errors.New("--rekor-url and --rekor-default can not be used simultaneously")
		}
		opts.rekorURL = defaultRekorURL
	}
	if opts.rekorURL == "" {
		return nil, errors.New("--rekor-url or --rekor-default must be specified")
	}

	payloadHash := sha256.Sum256(payloadBytes) // HashedRecord only accepts SHA-256
	// FIXME? Don't use the hashedrekor_v001 package at all, just models (and hard-code APIVersion), that might eliminate a few dependencies.
	rekorEntry := hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: swag.String(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
					Value:     swag.String(hex.EncodeToString(payloadHash[:])),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(signatureBytes),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(keyOrCertBytes),
				},
			},
		},
	}
	proposedEntry := models.Hashedrekord{
		APIVersion: swag.String(rekorEntry.APIVersion()),
		Spec:       rekorEntry.HashedRekordObj,
	}

	// Upload
	uploadedPayload, err := rekorUpload(ctx, opts.rekorURL, &proposedEntry)
	if err != nil {
		return nil, err
	}

	var storedEntry *models.LogEntryAnon
	for _, p := range uploadedPayload {
		storedEntry = &p // Assume there is exactly one
		break
	}

	rekorBundle := bundle.EntryToBundle(storedEntry)
	rekorSET, err := json.Marshal(rekorBundle)
	if err != nil {
		return nil, err
	}
	return rekorSET, nil
}
