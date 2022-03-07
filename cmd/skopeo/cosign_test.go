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

func runAndLogSkopeo(t *testing.T, args ...string) string {
	out, err := runSkopeo(args...)
	require.NoError(t, err)
	t.Logf("skopeo %s: %s", strings.Join(args, " "), out)
	return out
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

	runAndLogSkopeo(t, "--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://quay.io/libpod/alpine:3.10.2", "docker://"+cosignPristineTestImage)
}

func TestCosignStandaloneVerify(t *testing.T) {
	ensureTestImage(t)

	keys := generateKeys(t)

	testRepo := fmt.Sprintf("%s/test-repo-%d", cosignTempRegistry, rand.NewSource(time.Now().Unix()).Int63())
	testImage := testRepo + "/alpine:3.10.2"
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://"+cosignPristineTestImage, "docker://"+testImage)

	dir := t.TempDir()

	sigPath := filepath.Join(dir, "sig")
	cmd := exec.Command("cosign", "sign", "--tlog-upload=false", "--key", keys.priv, "--output-signature", sigPath, testImage)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=pass")
	run(t, cmd)

	imageDir := t.TempDir()
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testImage, "dir:"+imageDir)

	sigImageDir := t.TempDir()
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testRepo+"/alpine:sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f.sig", "dir:"+sigImageDir)
	sigRef, err := directory.NewReference(sigImageDir)
	require.NoError(t, err)
	sigSrc, err := sigRef.NewImageSource(context.Background(), nil)
	require.NoError(t, err)
	image, err := image.FromSource(context.Background(), nil, sigSrc)
	require.NoError(t, err)
	layers := image.LayerInfos()
	require.NotEmpty(t, layers)

	runAndLogSkopeo(t, "cosign-standalone-verify", "--public-key", keys.pub, "--require-rekor=false",
		filepath.Join(imageDir, "manifest.json"), filepath.Join(sigImageDir, layers[0].Digest.Encoded()), sigPath)
}

// FIXME: Also c/image policy verification for interoperability, both ways.

func TestCosignStandaloneRekorVerifyKeyOnly(t *testing.T) {
	ensureTestImage(t)

	keys := generateKeys(t)

	testRepo := fmt.Sprintf("%s/test-repo-%d", cosignTempRegistry, rand.NewSource(time.Now().Unix()).Int63())
	testImage := testRepo + "/alpine:3.10.2"
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://"+cosignPristineTestImage, "docker://"+testImage)

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "sig")
	setPath := filepath.Join(dir, "set")

	cmd := exec.Command("cosign", "sign", "--key", keys.priv, "--tlog-upload", "--output-signature", sigPath, testImage)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=pass")
	run(t, cmd)

	imageDir := t.TempDir()
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testImage, "dir:"+imageDir)

	sigImageDir := t.TempDir()
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testRepo+"/alpine:sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f.sig", "dir:"+sigImageDir)
	sigRef, err := directory.NewReference(sigImageDir)
	require.NoError(t, err)
	sigSrc, err := sigRef.NewImageSource(context.Background(), nil)
	require.NoError(t, err)
	image, err := image.FromSource(context.Background(), nil, sigSrc)
	require.NoError(t, err)
	layers := image.LayerInfos()
	require.NotEmpty(t, layers)
	setBlob, ok := layers[0].Annotations["dev.sigstore.cosign/bundle"]
	require.True(t, ok)
	err = os.WriteFile(setPath, []byte(setBlob), 0600)
	require.NoError(t, err)

	runAndLogSkopeo(t, "cosign-standalone-verify", "--public-key", keys.pub, "--require-rekor=true",
		"--rekor-set", setPath, filepath.Join(imageDir, "manifest.json"),
		filepath.Join(sigImageDir, layers[0].Digest.Encoded()), sigPath)
}

func TestCosignFulcioRekorVerify(t *testing.T) {
	ensureTestImage(t)

	testRepo := fmt.Sprintf("%s/test-repo-%d", cosignTempRegistry, rand.NewSource(time.Now().Unix()).Int63())
	testImage := testRepo + "/alpine:3.10.2"
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://"+cosignPristineTestImage, "docker://"+testImage)

	dir := t.TempDir()
	sigPath := filepath.Join(dir, "sig")
	setPath := filepath.Join(dir, "set")
	certPath := filepath.Join(dir, "cert")
	chainPath := filepath.Join(dir, "chain")

	func() {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			t.Skipf("No TTY for signing")
		}
		require.NoError(t, err)
		defer tty.Close()
		cmd := exec.Command("cosign", "sign", "--tlog-upload", "--output-signature", sigPath, "--output-certificate", certPath,
			"--yes", // Skip privacy prompt
			testImage)
		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
		err = cmd.Run()
		require.NoError(t, err)
	}()

	imageDir := t.TempDir()
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testImage, "dir:"+imageDir)

	sigImageDir := t.TempDir()
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testRepo+"/alpine:sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f.sig", "dir:"+sigImageDir)
	sigRef, err := directory.NewReference(sigImageDir)
	require.NoError(t, err)
	sigSrc, err := sigRef.NewImageSource(context.Background(), nil)
	require.NoError(t, err)
	image, err := image.FromSource(context.Background(), nil, sigSrc)
	require.NoError(t, err)
	layers := image.LayerInfos()
	require.NotEmpty(t, layers)
	setBlob, ok := layers[0].Annotations["dev.sigstore.cosign/bundle"]
	require.True(t, ok)
	err = os.WriteFile(setPath, []byte(setBlob), 0600)
	require.NoError(t, err)
	chainBlob, ok := layers[0].Annotations["dev.sigstore.cosign/chain"]
	require.True(t, ok)
	err = os.WriteFile(chainPath, []byte(chainBlob), 0600)
	require.NoError(t, err)

	runAndLogSkopeo(t, "cosign-standalone-verify",
		"--fulcio", "fixtures/fulcio_v1.crt.pem",
		"--fulcio-issuer", "https://github.com/login/oauth",
		"--fulcio-email", "mitr@redhat.com",
		"--require-rekor=true",
		"--embedded-cert", certPath, "--cert-chain", chainPath, "--rekor-set", setPath,
		filepath.Join(imageDir, "manifest.json"),
		filepath.Join(sigImageDir, layers[0].Digest.Encoded()), sigPath)
}

// FIXME: Test, or remove, the --ca mode
