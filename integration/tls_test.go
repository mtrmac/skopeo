package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/image-spec/specs-go"
	imgspecv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.podman.io/image/v5/oci/layout"
)

func TestTLS(t *testing.T) {
	suite.Run(t, &tlsSuite{})
}

type tlsSuite struct {
	suite.Suite
	defaultServer *tlsConfigServer
	tls12Server   *tlsConfigServer
	nonPQCserver  *tlsConfigServer
	pqcServer     *tlsConfigServer

	expected []expectedBehavior
}

var (
	_ = suite.SetupAllSuite(&tlsSuite{})
	_ = suite.TearDownAllSuite(&tlsSuite{})
)

type expectedBehavior struct {
	server     *tlsConfigServer
	tlsDetails string
	expected   string
}

func (s *tlsSuite) SetupSuite() {
	t := s.T()

	s.defaultServer = newServer(t, &tls.Config{})
	s.tls12Server = newServer(t, &tls.Config{
		MaxVersion: tls.VersionTLS12,
	})
	s.nonPQCserver = newServer(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
	})
	s.pqcServer = newServer(t, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	})

	s.expected = []expectedBehavior{
		{
			server:     s.defaultServer,
			tlsDetails: "fixtures/tls-details-anything.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},
		{
			server:     s.tls12Server,
			tlsDetails: "fixtures/tls-details-anything.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},
		{
			server:     s.nonPQCserver,
			tlsDetails: "fixtures/tls-details-anything.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},
		{
			server:     s.pqcServer,
			tlsDetails: "fixtures/tls-details-anything.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},

		{
			server:     s.defaultServer,
			tlsDetails: "fixtures/tls-details-1.3.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},
		{
			server:     s.tls12Server,
			tlsDetails: "fixtures/tls-details-1.3.yaml",
			expected:   `protocol version not supported`,
		},
		{
			server:     s.nonPQCserver,
			tlsDetails: "fixtures/tls-details-1.3.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},
		{
			server:     s.pqcServer,
			tlsDetails: "fixtures/tls-details-1.3.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},

		{
			server:     s.defaultServer,
			tlsDetails: "fixtures/tls-details-pqc-only.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},
		{
			server:     s.tls12Server,
			tlsDetails: "fixtures/tls-details-pqc-only.yaml",
			expected:   `protocol version not supported`,
		},
		{
			server:     s.nonPQCserver,
			tlsDetails: "fixtures/tls-details-pqc-only.yaml",
			expected:   `handshake failure`,
		},
		{
			server:     s.pqcServer,
			tlsDetails: "fixtures/tls-details-pqc-only.yaml",
			expected:   `\b418\b`, // "I'm a teapot"
		},
	}
}

func (s *tlsSuite) TearDownSuite() {
}

func (s *tlsSuite) TestDockerDaemon() {
	t := s.T()

	// Our server doesn’t perform client authentication, but the docker-daemon: option semantics
	// requires us to provide a certificate if we want to specify a CA.
	dockerCertPath := t.TempDir()
	caPath := filepath.Join(dockerCertPath, "ca.pem")

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	publicKey := &privateKey.PublicKey

	err = os.WriteFile(filepath.Join(dockerCertPath, "key.pem"), pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}), 0o644)
	require.NoError(t, err)

	referenceTime := time.Now()
	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "client",
		},
		NotBefore: referenceTime.Add(-1 * time.Minute),
		NotAfter:  referenceTime.Add(1 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dockerCertPath, "cert.pem"), pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), 0o644)
	require.NoError(t, err)

	for _, e := range s.expected {
		err := os.WriteFile(caPath, e.server.certBytes, 0o644)
		require.NoError(t, err)
		assertSkopeoFails(t, e.expected, "--tls-details", e.tlsDetails, "inspect", "--daemon-host", e.server.server.URL, "--cert-dir", dockerCertPath, "docker-daemon:repo:tag")
	}
}

func (s *tlsSuite) TestRegistry() {
	t := s.T()

	caDir := t.TempDir()
	caPath := filepath.Join(caDir, "ca.crt")

	for _, e := range s.expected {
		err := os.WriteFile(caPath, e.server.certBytes, 0o644)
		require.NoError(t, err)
		assertSkopeoFails(t, e.expected, "--tls-details", e.tlsDetails, "inspect", "--cert-dir", caDir, "docker://"+e.server.hostPort+"/repo")
	}
}

func (s *tlsSuite) TestOCILayout() {
	t := s.T()

	caDir := t.TempDir()
	caPath := filepath.Join(caDir, "ca.crt")

	for _, e := range s.expected {
		err := os.WriteFile(caPath, e.server.certBytes, 0o644)
		require.NoError(t, err)

		ociLayoutDir := t.TempDir()
		destRef, err := layout.NewReference(ociLayoutDir, "repo:tag")
		require.NoError(t, err)
		dest, err := destRef.NewImageDestination(context.Background(), nil)
		require.NoError(t, err)
		manifestBytes, err := json.Marshal(imgspecv1.Manifest{
			Versioned: specs.Versioned{SchemaVersion: 2},
			MediaType: imgspecv1.MediaTypeImageManifest,
			Config: imgspecv1.Descriptor{
				MediaType: imgspecv1.MediaTypeImageConfig,
				Digest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Size:      42,
				URLs:      []string{e.server.server.URL + "/config.json"},
			},
			Layers:       []imgspecv1.Descriptor{},
			ArtifactType: "",
			Subject:      &imgspecv1.Descriptor{},
			Annotations:  map[string]string{},
		})
		require.NoError(t, err)
		err = dest.PutManifest(context.Background(), manifestBytes, nil)
		require.NoError(t, err)
		err = dest.Commit(context.Background(), nil) // nil is technically invalid, but works here
		require.NoError(t, err)
		err = dest.Close()
		require.NoError(t, err)

		// We don’t expose types.OCICertPath in the CLI. But if we get far enough to be worrying about certificates,
		// we already negotiated the TLS version and named group.
		expected := e.expected
		if expected == `\b418\b` {
			expected = `certificate signed by unknown authority`
		}
		assertSkopeoFails(t, expected, "--tls-details", e.tlsDetails, "inspect", "oci:"+ociLayoutDir)
	}
}

func (s *tlsSuite) TestOpenShift() {
	t := s.T()

	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "kubeconfig")
	t.Setenv("KUBECONFIG", configPath)

	for _, e := range s.expected {
		err := os.WriteFile(configPath, []byte(fmt.Sprintf(
			`apiVersion: v1
clusters:
- cluster:
    certificate-authority: "%s"
    server: "%s"
  name: our-cluster
contexts:
- context:
    cluster: our-cluster
    namespace: default
  name: our-context
current-context: our-context
kind: Config
`, e.server.certPath, e.server.server.URL)), 0o644)
		require.NoError(t, err)
		// The atomic: image access starts with resolving the tag in a k8s API (and that will always fail, one way or another),
		// so we never actually contact registry.example.
		assertSkopeoFails(t, e.expected, "--tls-details", e.tlsDetails, "inspect", "atomic:registry.example/namespace/repo:tag")
	}
}

// tlsConfigServer serves TLS with a specific configuration.
// It returns StatusTeapot on all requests; we use that to detect that the TLS negotiation succeeded,
// without bothering to actually implement any of the protocols.
type tlsConfigServer struct {
	server    *httptest.Server
	hostPort  string
	certBytes []byte
	certPath  string
}

func newServer(t *testing.T, config *tls.Config) *tlsConfigServer {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(server.Close)

	server.TLS = config.Clone()
	server.StartTLS()

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	certDir := t.TempDir()
	certPath := filepath.Join(certDir, "cert.pem")
	err := os.WriteFile(certPath, certBytes, 0o644)
	require.NoError(t, err)

	return &tlsConfigServer{
		server:    server,
		hostPort:  server.Listener.Addr().String(),
		certBytes: certBytes,
		certPath:  certPath,
	}
}
