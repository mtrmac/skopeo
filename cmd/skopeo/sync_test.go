package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.podman.io/image/v5/types"
	"gopkg.in/yaml.v3"
)

var _ yaml.Unmarshaler = (*tlsVerifyConfig)(nil)

func TestTLSVerifyConfig(t *testing.T) {
	type container struct { // An example of a larger config file
		TLSVerify tlsVerifyConfig `yaml:"tls-verify"`
	}

	for _, c := range []struct {
		input    string
		expected tlsVerifyConfig
	}{
		{
			input:    `tls-verify: true`,
			expected: tlsVerifyConfig{skip: types.OptionalBoolFalse},
		},
		{
			input:    `tls-verify: false`,
			expected: tlsVerifyConfig{skip: types.OptionalBoolTrue},
		},
		{
			input:    ``, // No value
			expected: tlsVerifyConfig{skip: types.OptionalBoolUndefined},
		},
	} {
		config := container{}
		err := yaml.Unmarshal([]byte(c.input), &config)
		require.NoError(t, err, c.input)
		assert.Equal(t, c.expected, config.TLSVerify, c.input)
	}

	// Invalid input
	config := container{}
	err := yaml.Unmarshal([]byte(`tls-verify: "not a valid bool"`), &config)
	assert.Error(t, err)
}

func TestSync(t *testing.T) {
	// Invalid command-line arguments
	for _, args := range [][]string{
		{},
		{"a1"},
		{"a1", "a2", "a3"},
	} {
		out, err := runSkopeo(append([]string{"sync"}, args...)...)
		assertTestFailed(t, out, err, "Exactly two arguments expected")
	}

	// FIXME: Much more test coverage
	// Actual feature tests exist in integration and systemtest
}

// TestSyncTLSPrecedence validates the interactions of tls-verify in YAML and --src-tls-verify in the CLI.
func TestSyncTLSPrecedence(t *testing.T) {
	for _, tt := range []struct {
		name               string
		incomingSkip       types.OptionalBool
		incomingDaemonSkip bool
		yaml               string
		wantSkip           types.OptionalBool
		wantDaemonSkip     bool
	}{
		{
			name:               "YAML omitted preserves incoming skip=true",
			incomingSkip:       types.OptionalBoolTrue,
			incomingDaemonSkip: true,
			yaml:               `# nothing`,
			wantSkip:           types.OptionalBoolTrue,
			wantDaemonSkip:     true,
		},
		{
			name:               "YAML omitted preserves incoming skip=false (CLI pass verify)",
			incomingSkip:       types.OptionalBoolFalse,
			incomingDaemonSkip: false,
			yaml:               `# nothing`,
			wantSkip:           types.OptionalBoolFalse,
			wantDaemonSkip:     false,
		},
		{
			name:               "YAML omitted preserves daemon skip=true while docker skip=undefined",
			incomingSkip:       types.OptionalBoolUndefined,
			incomingDaemonSkip: true,
			yaml:               `# nothing`,
			wantSkip:           types.OptionalBoolUndefined,
			wantDaemonSkip:     true,
		},
		{
			name:               "YAML omitted preserves mismatched incoming (docker skip=true, daemon skip=false)",
			incomingSkip:       types.OptionalBoolTrue,
			incomingDaemonSkip: false,
			yaml:               `# nothing`,
			wantSkip:           types.OptionalBoolTrue,
			wantDaemonSkip:     false,
		},
		{
			name:               "YAML tls-verify:true enforces verification",
			incomingSkip:       types.OptionalBoolTrue,
			incomingDaemonSkip: true,
			yaml:               "tls-verify: true",
			wantSkip:           types.OptionalBoolFalse,
			wantDaemonSkip:     false,
		},
		{
			name:               "YAML tls-verify:false disables verification",
			incomingSkip:       types.OptionalBoolFalse,
			incomingDaemonSkip: false,
			yaml:               "tls-verify: false",
			wantSkip:           types.OptionalBoolTrue,
			wantDaemonSkip:     true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := types.SystemContext{
				DockerInsecureSkipTLSVerify:       tt.incomingSkip,
				DockerDaemonInsecureSkipTLSVerify: tt.incomingDaemonSkip,
			}
			var cfg registrySyncConfig
			err := yaml.Unmarshal(fmt.Appendf(nil, `
%s
images:
  repo: # Specifying an explicit repo+tag avoids imagesToCopyFromRegistry trying to contact the registry.
    - latest
`, tt.yaml,
			), &cfg)
			require.NoError(t, err)

			descs, err := imagesToCopyFromRegistry("example.com", cfg, src)
			require.NoError(t, err)
			require.NotEmpty(t, descs)
			ctx := descs[0].Context
			require.NotNil(t, ctx)
			assert.Equal(t, tt.wantSkip, ctx.DockerInsecureSkipTLSVerify)
			assert.Equal(t, tt.wantDaemonSkip, ctx.DockerDaemonInsecureSkipTLSVerify)
		})
	}
}
