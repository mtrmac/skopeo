package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containers/image/v5/directory"
	"github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/image"
	"github.com/containers/image/v5/types"
	"github.com/stretchr/testify/require"
)

// Requires cosignTempRegistry from cosign_uncommitted_test.go

const cosignPristineTestImage = cosignTempRegistry + "/pristine/alpine:3.10.2"

var dirCount atomic.Int32

func tempDir(t *testing.T) string {
	if dir := os.Getenv("SKOPEO_TEMP_PRESERVE"); dir != "" {
		i := dirCount.Add(1)
		path := filepath.Join(dir, fmt.Sprintf("%d", i))
		err := os.MkdirAll(path, 0o700)
		require.NoError(t, err)
		return path
	}
	return t.TempDir()
}

type keys struct {
	pub, priv  string
	passphrase string
}

func run(t *testing.T, cmd *exec.Cmd) {
	commandText := fmt.Sprintf("%s %s", cmd.Path, strings.Join(cmd.Args, " "))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out), commandText)
	t.Logf("%s: %s", commandText, out)
}

func runAndLogSkopeo(t *testing.T, args ...string) string {
	commandText := fmt.Sprintf("skopeo %s", strings.Join(args, " "))
	out, err := runSkopeo(args...)
	require.NoError(t, err, commandText)
	t.Logf("%s: %s", commandText, out)
	return out
}

func generateKeys(t *testing.T) keys {
	passphrase := "pass"
	dir := tempDir(t)
	cmd := exec.Command("cosign", "generate-key-pair")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+passphrase)
	run(t, cmd)
	return keys{
		priv:       filepath.Join(dir, "cosign.key"),
		pub:        filepath.Join(dir, "cosign.pub"),
		passphrase: passphrase,
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

	dir := tempDir(t)

	sigPath := filepath.Join(dir, "sig")
	cmd := exec.Command("cosign", "sign", "--recursive", "--tlog-upload=false", "--key", keys.priv, "--output-signature", sigPath, testImage)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+keys.passphrase)
	run(t, cmd)
	sigImageRegistryRef := "docker://" + testRepo + "/alpine:sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f.sig"

	imageDir := tempDir(t)
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testImage, "dir:"+imageDir)

	sigImageDir := tempDir(t)
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", sigImageRegistryRef, "dir:"+sigImageDir)
	sigRef, err := directory.NewReference(sigImageDir)
	require.NoError(t, err)
	sigSrc, err := sigRef.NewImageSource(context.Background(), nil)
	require.NoError(t, err)
	image, err := image.FromSource(context.Background(), nil, sigSrc)
	require.NoError(t, err)
	layers := image.LayerInfos()
	require.NotEmpty(t, layers)

	runAndLogSkopeo(t, "cosign-standalone-verify", "--public-key", keys.pub,
		filepath.Join(imageDir, "manifest.json"), filepath.Join(sigImageDir, layers[0].Digest.Encoded()), sigPath+"-sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f")
	runAndLogSkopeo(t, "--registries.d", "fixtures/registries.d",
		"cosign-image-verify", "--tls-verify=false", "--public-key", keys.pub,
		"docker://"+testImage)
}

// FIXME: Also c/image policy verification for interoperability, both ways.

func TestCosignStandaloneRekorVerifyKeyOnly(t *testing.T) {
	ensureTestImage(t)

	keys := generateKeys(t)

	testRepo := fmt.Sprintf("%s/test-repo-%d", cosignTempRegistry, rand.NewSource(time.Now().Unix()).Int63())
	testImage := testRepo + "/alpine:3.10.2"
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://"+cosignPristineTestImage, "docker://"+testImage)

	dir := tempDir(t)
	sigPath := filepath.Join(dir, "sig")
	setPath := filepath.Join(dir, "set")

	cmd := exec.Command("cosign", "sign", "--key", keys.priv, "--tlog-upload", "--output-signature", sigPath, testImage)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD="+keys.passphrase)
	run(t, cmd)
	sigImageRegistryRef := "docker://" + testRepo + "/alpine:sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f.sig"

	imageDir := tempDir(t)
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testImage, "dir:"+imageDir)

	sigImageDir := tempDir(t)
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", sigImageRegistryRef, "dir:"+sigImageDir)
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

	runAndLogSkopeo(t, "cosign-standalone-verify", "--public-key", keys.pub, "--rekor", "fixtures/rekor.pub",
		"--rekor-set", setPath, filepath.Join(imageDir, "manifest.json"),
		filepath.Join(sigImageDir, layers[0].Digest.Encoded()), sigPath)
	runAndLogSkopeo(t, "--registries.d", "fixtures/registries.d",
		"cosign-image-verify", "--tls-verify=false", "--public-key", keys.pub, "--rekor", "fixtures/rekor.pub",
		"docker://"+testImage)
}

func TestCosignFulcioRekorVerify(t *testing.T) {
	ensureTestImage(t)

	testRepo := fmt.Sprintf("%s/test-repo-%d", cosignTempRegistry, rand.NewSource(time.Now().Unix()).Int63())
	testImage := testRepo + "/alpine:3.10.2"
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--dest-tls-verify=false", "--src-tls-verify=false", "--all",
		"docker://"+cosignPristineTestImage, "docker://"+testImage)

	dir := tempDir(t)
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
	sigImageRegistryRef := "docker://" + testRepo + "/alpine:sha256-fa93b01658e3a5a1686dc3ae55f170d8de487006fb53a28efcd12ab0710a2e5f.sig"

	imageDir := tempDir(t)
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", "docker://"+testImage, "dir:"+imageDir)

	sigImageDir := tempDir(t)
	runAndLogSkopeo(t, "--insecure-policy", "copy", "--all", "--src-tls-verify=false", sigImageRegistryRef, "dir:"+sigImageDir)
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
		"--rekor", "fixtures/rekor.pub",
		"--embedded-cert", certPath, "--cert-chain", chainPath, "--rekor-set", setPath,
		filepath.Join(imageDir, "manifest.json"),
		filepath.Join(sigImageDir, layers[0].Digest.Encoded()), sigPath)
	runAndLogSkopeo(t, "--registries.d", "fixtures/registries.d",
		"cosign-image-verify", "--tls-verify=false",
		"--fulcio", "fixtures/fulcio_v1.crt.pem",
		"--fulcio-issuer", "https://github.com/login/oauth",
		"--fulcio-email", "mitr@redhat.com",
		"--rekor", "fixtures/rekor.pub",
		"docker://"+testImage)
}

// FIXME: Test, or remove, the --ca mode

func TestCosignRekorUpload(t *testing.T) {
	ensureTestImage(t)

	keys := generateKeys(t)

	dir := tempDir(t)
	manifestPath := filepath.Join(dir, "manifest")
	sigPath := filepath.Join(dir, "signature")
	payloadPath := filepath.Join(dir, "payload")
	passphrasePath := filepath.Join(dir, "pass")
	setPath := filepath.Join(dir, "set")

	ref, err := docker.ParseReference("//" + cosignPristineTestImage)
	require.NoError(t, err)
	src, err := ref.NewImageSource(context.Background(), &types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue})
	require.NoError(t, err)
	manifestBlob, _, err := src.GetManifest(context.Background(), nil)
	require.NoError(t, err)
	err = os.WriteFile(manifestPath, manifestBlob, 0o600)
	require.NoError(t, err)

	err = os.WriteFile(passphrasePath, []byte(keys.passphrase), 0o600)
	require.NoError(t, err)
	runAndLogSkopeo(t, "cosign-standalone-sign", manifestPath, cosignPristineTestImage,
		"--key", keys.priv, "--key-passphrase-file", passphrasePath,
		"--signature", sigPath, "--payload", payloadPath)
	runAndLogSkopeo(t, "cosign-rekor-upload", "--rekor-default",
		keys.pub, sigPath, payloadPath, "-o", setPath)

	cmd := exec.Command("cosign", "verify-blob", "--key", keys.pub, "--signature", sigPath, "--bundle", setPath, payloadPath)
	run(t, cmd)

	runAndLogSkopeo(t, "cosign-standalone-verify", "--public-key", keys.pub, "--rekor", "fixtures/rekor.pub",
		"--rekor-set", setPath, manifestPath, payloadPath, sigPath)
}

func TestCosignStandaloneSign(t *testing.T) {
	keys := generateKeys(t)

	dir := tempDir(t)
	manifestPath := filepath.Join(dir, "manifest")
	sigPath := filepath.Join(dir, "signature")
	payloadPath := filepath.Join(dir, "payload")
	passphrasePath := filepath.Join(dir, "pass")
	setPath := filepath.Join(dir, "set")

	ref, err := docker.ParseReference("//" + cosignPristineTestImage)
	require.NoError(t, err)
	src, err := ref.NewImageSource(context.Background(), &types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue})
	require.NoError(t, err)
	manifestBlob, _, err := src.GetManifest(context.Background(), nil)
	require.NoError(t, err)
	err = os.WriteFile(manifestPath, manifestBlob, 0o600)
	require.NoError(t, err)

	err = os.WriteFile(passphrasePath, []byte(keys.passphrase), 0o600)
	require.NoError(t, err)
	runAndLogSkopeo(t, "cosign-standalone-sign", manifestPath, cosignPristineTestImage, "--rekor-default",
		"--key", keys.priv, "--key-passphrase-file", passphrasePath,
		"--signature", sigPath, "--payload", payloadPath, "--rekor-set", setPath)

	cmd := exec.Command("cosign", "verify-blob", "--key", keys.pub, "--signature", sigPath, "--bundle", setPath, payloadPath)
	run(t, cmd)

	runAndLogSkopeo(t, "cosign-standalone-verify", "--public-key", keys.pub, "--rekor", "fixtures/rekor.pub",
		"--rekor-set", setPath, manifestPath, payloadPath, sigPath)
}

func TestCosignStandaloneFulcioSign(t *testing.T) {
	dir := tempDir(t)
	manifestPath := filepath.Join(dir, "manifest")
	sigPath := filepath.Join(dir, "signature")
	payloadPath := filepath.Join(dir, "payload")
	certPath := filepath.Join(dir, "cert")
	chainPath := filepath.Join(dir, "chain")
	setPath := filepath.Join(dir, "set")

	ref, err := docker.ParseReference("//" + cosignPristineTestImage)
	require.NoError(t, err)
	src, err := ref.NewImageSource(context.Background(), &types.SystemContext{DockerInsecureSkipTLSVerify: types.OptionalBoolTrue})
	require.NoError(t, err)
	manifestBlob, _, err := src.GetManifest(context.Background(), nil)
	require.NoError(t, err)
	err = os.WriteFile(manifestPath, manifestBlob, 0o600)
	require.NoError(t, err)

	runAndLogSkopeo(t, "cosign-standalone-sign", manifestPath, cosignPristineTestImage,
		"--fulcio-default", "--rekor-default",
		"--certificate", certPath, "--certificate-chain", chainPath,
		"--signature", sigPath, "--payload", payloadPath, "--rekor-set", setPath)

	cmd := exec.Command("cosign", "verify-blob", "--certificate", certPath, "--certificate-chain", chainPath,
		"--certificate-oidc-issuer", "https://github.com/login/oauth",
		"--certificate-email", "mitr@redhat.com",
		"--verbose",
		"--signature", sigPath, "--bundle", setPath, payloadPath)
	run(t, cmd)

	runAndLogSkopeo(t, "cosign-standalone-verify",
		"--fulcio", "fixtures/fulcio_v1.crt.pem",
		"--fulcio-issuer", "https://github.com/login/oauth",
		"--fulcio-email", "mitr@redhat.com",
		"--rekor", "fixtures/rekor.pub",
		"--embedded-cert", certPath, "--cert-chain", chainPath, "--rekor-set", setPath,
		manifestPath, payloadPath, sigPath)
}

// TO DO: Fulcio sign + Rekor upload, as an image

// bin/skopeo --registries.d cmd/skopeo/fixtures/registries.d --override-os linux --tls-verify=false --insecure-policy
//	copy --debug --sign-by-sigstore=FIXME-param-key docker://$reg/pristine/alpine:3.10.2 docker://$reg/manual/key-rekor
// cosign verify --key cosign-preserve/1/cosign.pub $reg/manual/key-rekor

// bin/skopeo --registries.d cmd/skopeo/fixtures/registries.d --override-os linux --tls-verify=false --insecure-policy
//	copy --debug --sign-by-sigstore=FIXME-fulcio-device docker://$reg/pristine/alpine:3.10.2 docker://$reg/manual/fulcio-device-1
// cosign verify $reg/manual/fulcio-device-1

// bin/skopeo --registries.d cmd/skopeo/fixtures/registries.d --override-os linux --tls-verify=false --insecure-policy
//	copy --debug --sign-by-sigstore=FIXME-fulcio-interactive docker://$reg/pristine/alpine:3.10.2 docker://$reg/manual/fulcio-interactive-1
// cosign verify $reg/manual/fulcio-interactive-1
