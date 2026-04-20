package jsonproxy

import (
	"errors"

	dockerdistributionerrcode "github.com/docker/distribution/registry/api/errcode"
	dockerdistributionapi "github.com/docker/distribution/registry/api/v2"
	ociarchive "go.podman.io/image/v5/oci/archive"
	ocilayout "go.podman.io/image/v5/oci/layout"
	"go.podman.io/image/v5/storage"
)

// isNotFoundImageError checks if an error indicates that an image was not found.
func isNotFoundImageError(err error) bool {
	var layoutImageNotFoundError ocilayout.ImageNotFoundError
	var archiveImageNotFoundError ociarchive.ImageNotFoundError
	return isDockerManifestUnknownError(err) ||
		errors.Is(err, storage.ErrNoSuchImage) ||
		errors.As(err, &layoutImageNotFoundError) ||
		errors.As(err, &archiveImageNotFoundError)
}

// isDockerManifestUnknownError checks if an error is a Docker manifest unknown error.
func isDockerManifestUnknownError(err error) bool {
	var ec dockerdistributionerrcode.ErrorCoder
	if !errors.As(err, &ec) {
		return false
	}
	return ec.ErrorCode() == dockerdistributionapi.ErrorCodeManifestUnknown
}
