package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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

func TestCosignStandaloneVerify(t *testing.T) {
	keys := generateKeys(t)

	dir := t.TempDir()
	blobPath := filepath.Join(dir, "blob")
	sigPath := filepath.Join(dir, "sig")
	err := os.WriteFile(blobPath, []byte("hello"), 0o600)
	require.NoError(t, err)
	cmd := exec.Command("cosign", "sign-blob", "--key", keys.priv, "--output-signature", sigPath, blobPath)
	cmd.Env = append(os.Environ(), "COSIGN_PASSWORD=pass")
	run(t, cmd)

	out, err := runSkopeo("cosign-standalone-verify", "--public-key", keys.pub, blobPath, sigPath)
	require.NoError(t, err)
	t.Logf("cosign-standalone-verify: %s", out)
}
