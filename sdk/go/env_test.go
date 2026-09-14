package objectio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Mirrored by sdk/python/tests/test_env.py.

var allVars = []string{
	EnvEndpoint, EnvURL,
	EnvAccessKey, EnvAccessKeyFile,
	EnvSecretKey, EnvSecretKeyFile,
	EnvRegion, EnvProvisionerUserID,
	"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "AWS_DEFAULT_REGION",
}

// cleanEnv unsets every variable the loader looks at, so a developer's own
// AWS credentials cannot make a test pass that would fail in CI.
func cleanEnv(t *testing.T) {
	t.Helper()
	for _, name := range allVars {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
}

func TestConfigFromEnvReadsTheObjectIONames(t *testing.T) {
	cleanEnv(t)
	t.Setenv(EnvEndpoint, "https://s3.example.com")
	t.Setenv(EnvAccessKey, "AKIA1")
	t.Setenv(EnvSecretKey, "s3cret")
	t.Setenv(EnvRegion, "eu-west-1")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "https://s3.example.com" || cfg.AccessKey != "AKIA1" ||
		cfg.SecretKey != "s3cret" || cfg.Region != "eu-west-1" {
		t.Errorf("got %+v", cfg)
	}
}

func TestObjectIOURLIsASynonym(t *testing.T) {
	cleanEnv(t)
	t.Setenv(EnvURL, "https://s3.example.com")
	t.Setenv(EnvAccessKey, "AKIA1")
	t.Setenv(EnvSecretKey, "s3cret")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Endpoint != "https://s3.example.com" {
		t.Errorf("Endpoint = %q", cfg.Endpoint)
	}
}

func TestFallsBackToTheAWSNames(t *testing.T) {
	// A pod that already carries AWS credentials for its S3 client should not
	// need a second copy under different names.
	cleanEnv(t)
	t.Setenv(EnvEndpoint, "https://s3.example.com")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAWS")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "awssecret")
	t.Setenv("AWS_DEFAULT_REGION", "ap-south-1")

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessKey != "AKIAAWS" || cfg.SecretKey != "awssecret" || cfg.Region != "ap-south-1" {
		t.Errorf("got %+v", cfg)
	}
}

func TestObjectIONamesWinOverAWS(t *testing.T) {
	cleanEnv(t)
	t.Setenv(EnvEndpoint, "https://s3.example.com")
	t.Setenv(EnvAccessKey, "AKIAOWN")
	t.Setenv(EnvSecretKey, "own")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAAWS")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "awssecret")

	cfg, _ := ConfigFromEnv()
	if cfg.AccessKey != "AKIAOWN" || cfg.SecretKey != "own" {
		t.Errorf("got %+v", cfg)
	}
}

func TestSecretFromFileStripsTheTrailingNewline(t *testing.T) {
	// The bug the TrimSpace exists for: a projected Kubernetes Secret ends in
	// a newline, and a "\n" inside the signing key produces a
	// SignatureDoesNotMatch that reads like a wrong password.
	cleanEnv(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	access := filepath.Join(dir, "access")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(access, []byte("AKIAFILE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvEndpoint, "https://s3.example.com")
	t.Setenv(EnvAccessKeyFile, access)
	t.Setenv(EnvSecretKeyFile, secret)

	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessKey != "AKIAFILE" || cfg.SecretKey != "s3cret" {
		t.Errorf("got AccessKey=%q SecretKey=%q", cfg.AccessKey, cfg.SecretKey)
	}
}

func TestFileWinsOverInlineValue(t *testing.T) {
	cleanEnv(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvEndpoint, "https://s3.example.com")
	t.Setenv(EnvAccessKey, "AKIA1")
	t.Setenv(EnvSecretKey, "from-env")
	t.Setenv(EnvSecretKeyFile, secret)

	cfg, _ := ConfigFromEnv()
	if cfg.SecretKey != "from-file" {
		t.Errorf("SecretKey = %q", cfg.SecretKey)
	}
}

func TestRegionDefaultsThroughNew(t *testing.T) {
	cleanEnv(t)
	t.Setenv(EnvEndpoint, "https://s3.example.com")
	t.Setenv(EnvAccessKey, "AKIA1")
	t.Setenv(EnvSecretKey, "s")

	c, err := NewFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.region != "us-east-1" {
		t.Errorf("region = %q", c.region)
	}
}

func TestMissingSettingsNameThemselves(t *testing.T) {
	cases := []struct {
		name    string
		set     map[string]string
		wantSub string
	}{
		{"no endpoint", map[string]string{EnvAccessKey: "a", EnvSecretKey: "b"}, EnvEndpoint},
		{"no access key", map[string]string{EnvEndpoint: "https://x", EnvSecretKey: "b"}, EnvAccessKey},
		{"no secret key", map[string]string{EnvEndpoint: "https://x", EnvAccessKey: "a"}, EnvSecretKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tc.set {
				t.Setenv(k, v)
			}
			_, err := ConfigFromEnv()
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not name %s", err, tc.wantSub)
			}
		})
	}
}

func TestUnreadableSecretFileIsAnError(t *testing.T) {
	cleanEnv(t)
	t.Setenv(EnvEndpoint, "https://s3.example.com")
	t.Setenv(EnvAccessKey, "AKIA1")
	t.Setenv(EnvSecretKeyFile, filepath.Join(t.TempDir(), "nope"))

	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("expected an error for a missing secret file")
	}
}

func TestProvisionerUserIDFromEnv(t *testing.T) {
	cleanEnv(t)
	if got := ProvisionerUserIDFromEnv(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	t.Setenv(EnvProvisionerUserID, " abc-123 \n")
	if got := ProvisionerUserIDFromEnv(); got != "abc-123" {
		t.Errorf("got %q", got)
	}
}
