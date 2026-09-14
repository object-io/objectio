package objectio

import (
	"fmt"
	"os"
	"strings"
)

// Environment variables read by NewFromEnv and ConfigFromEnv.
//
// The AWS names are accepted as fallbacks so one set of variables configures
// both this client and whatever S3 SDK sits beside it — a pod that already has
// AWS_ACCESS_KEY_ID for mountpoint-s3 needs nothing extra.
const (
	EnvEndpoint = "OBJECTIO_ENDPOINT"
	// EnvURL is accepted as a synonym for EnvEndpoint.
	EnvURL       = "OBJECTIO_URL"
	EnvAccessKey = "OBJECTIO_ACCESS_KEY"
	EnvSecretKey = "OBJECTIO_SECRET_KEY"
	// EnvSecretKeyFile points at a file holding the secret — how a Kubernetes
	// Secret is normally projected. Prefer it: a value in the environment is
	// readable from /proc, lands in crash dumps, and shows up in `kubectl
	// describe pod` when it was set inline rather than from a secretRef.
	EnvSecretKeyFile = "OBJECTIO_SECRET_KEY_FILE"
	// EnvAccessKeyFile is the matching file for the access key ID. Less
	// important — the ID is not a secret — but symmetric.
	EnvAccessKeyFile = "OBJECTIO_ACCESS_KEY_FILE"
	EnvRegion        = "OBJECTIO_REGION"
	// EnvProvisionerUserID is the provisioner's own user_id, which
	// ProvisionWorkspace needs. Not used by ConfigFromEnv; read it with
	// ProvisionerUserIDFromEnv.
	EnvProvisionerUserID = "OBJECTIO_PROVISIONER_USER_ID"
)

// readValue resolves one setting from, in order: a *_FILE variable, a direct
// variable, then any fallback names.
//
// File contents are trimmed of surrounding whitespace. A mounted secret
// almost always ends in a newline, and a trailing "\n" inside a signing key
// produces a SignatureDoesNotMatch that looks like a wrong password.
func readValue(fileEnv, directEnv string, fallbacks ...string) (string, error) {
	if path := os.Getenv(fileEnv); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("objectio: reading %s=%s: %w", fileEnv, path, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if v := os.Getenv(directEnv); v != "" {
		return strings.TrimSpace(v), nil
	}
	for _, name := range fallbacks {
		if v := os.Getenv(name); v != "" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", nil
}

// ConfigFromEnv builds a Config from the environment.
//
//	OBJECTIO_ENDPOINT     | OBJECTIO_URL                          (required)
//	OBJECTIO_ACCESS_KEY   | OBJECTIO_ACCESS_KEY_FILE | AWS_ACCESS_KEY_ID
//	OBJECTIO_SECRET_KEY   | OBJECTIO_SECRET_KEY_FILE | AWS_SECRET_ACCESS_KEY
//	OBJECTIO_REGION       | AWS_REGION | AWS_DEFAULT_REGION        (default us-east-1)
//
// The credential must be unscoped: a key confined to a bucket is refused on
// the management API.
func ConfigFromEnv() (Config, error) {
	endpoint, err := readValue("", EnvEndpoint, EnvURL)
	if err != nil {
		return Config{}, err
	}
	if endpoint == "" {
		return Config{}, fmt.Errorf("objectio: %s (or %s) is not set", EnvEndpoint, EnvURL)
	}

	accessKey, err := readValue(EnvAccessKeyFile, EnvAccessKey, "AWS_ACCESS_KEY_ID")
	if err != nil {
		return Config{}, err
	}
	if accessKey == "" {
		return Config{}, fmt.Errorf("objectio: %s, %s or AWS_ACCESS_KEY_ID is not set",
			EnvAccessKey, EnvAccessKeyFile)
	}

	secretKey, err := readValue(EnvSecretKeyFile, EnvSecretKey, "AWS_SECRET_ACCESS_KEY")
	if err != nil {
		return Config{}, err
	}
	if secretKey == "" {
		return Config{}, fmt.Errorf("objectio: %s, %s or AWS_SECRET_ACCESS_KEY is not set",
			EnvSecretKey, EnvSecretKeyFile)
	}

	region, err := readValue("", EnvRegion, "AWS_REGION", "AWS_DEFAULT_REGION")
	if err != nil {
		return Config{}, err
	}

	return Config{
		Endpoint:  endpoint,
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    region,
	}, nil
}

// NewFromEnv is ConfigFromEnv followed by New. This is the constructor a
// deployed provisioner wants.
func NewFromEnv() (*Client, error) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return New(cfg)
}

// ProvisionerUserIDFromEnv reads OBJECTIO_PROVISIONER_USER_ID, the user that
// ProvisionWorkspace mints workspace credentials on. Empty when unset —
// callers that can discover it another way need not set it.
func ProvisionerUserIDFromEnv() string {
	return strings.TrimSpace(os.Getenv(EnvProvisionerUserID))
}
