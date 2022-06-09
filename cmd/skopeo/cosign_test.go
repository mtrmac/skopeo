package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/directory"
	"go.podman.io/image/v5/docker"
	"go.podman.io/image/v5/image"
	"go.podman.io/image/v5/types"
)

// Requires cosignTempRegistry from cosign_uncommitted_test.go

const cosignPristineTestImage = cosignTempRegistry + "/pristine/alpine:3.10.2"

type keys struct {
	pub, priv string
}

func run(t *testing.T, cmd *exec.Cmd) {
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	t.Logf("%s %s: %s", cmd.Path, strings.Join(cmd.Args, " "), out)
}

func generateKeys(t *testing.T) keys {
	dir := t.TempDir()
	cmd := exec.Command("cosign", "generate-key-pair")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=pass")
	run(t, cmd)
	return keys{
		priv: filepath.Join(dir, "cosign.key"),
		pub:  filepath.Join(dir, "cosign.pub"),
	}
}

func ensureTestImage(t *testing.T) {
	ref, err := docker.ParseReference("//" + cosignPristineTestImage)
	require.NoError(t, err)
	src, err := ref.NewImageSource(context.Background(), &types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue})
	if err == nil {
		src.Close()
		return
	}
	t.Logf("pristine test image missing, creating it")

	out, err := runSkopeo("--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://quay.io/libpod/alpine:3.10.2", "docker://"+cosignPristineTestImage)
	require.NoError(t, err)
	t.Logf("copy: %s", out)
}

func TestCosignStandaloneVerify(t *testing.T) {
	ensureTestImage(t)

	keys := generateKeys(t)

	testRepo := fmt.Sprintf("%s/test-repo-%d", cosignTempRegistry, rand.NewSource(time.Now().Unix()).Int63())
	testImage := testRepo + "/alpine:3.10.2"
	out, err := runSkopeo("--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://"+cosignPristineTestImage, "docker://"+testImage)
	require.NoError(t, err)
	t.Logf("copy: %s", out)

	dir := t.TempDir()

	sigPath := filepath.Join(dir, "sig")
	cmd := exec.Command("cosign", "sign", "--tlog-upload=false", "--key", keys.priv, "--output-signature", sigPath, testImage)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=pass")
	run(t, cmd)

	imageDir := t.TempDir()
	out, err = runSkopeo("--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testImage, "dir:"+imageDir)
	require.NoError(t, err)
	t.Logf("copy: %s", out)

	sigImageDir := t.TempDir()
	out, err = runSkopeo("--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testRepo+"/alpine:sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f.sig", "dir:"+sigImageDir)
	require.NoError(t, err)
	t.Logf("copy: %s", out)
	sigRef, err := directory.NewReference(sigImageDir)
	require.NoError(t, err)
	sigSrc, err := sigRef.NewImageSource(context.Background(), nil)
	require.NoError(t, err)
	image, err := image.FromSource(context.Background(), nil, sigSrc)
	require.NoError(t, err)
	layers := image.LayerInfos()
	require.NotEmpty(t, layers)

	out, err = runSkopeo("cosign-standalone-verify", "--public-key", keys.pub, filepath.Join(imageDir, "manifest.json"),
		filepath.Join(sigImageDir, layers[0].Digest.Encoded()), sigPath)
	require.NoError(t, err)
	t.Logf("cosign-standalone-verify: %s", out)
}
