// Package objectio is a client for the ObjectIO **management API** — the
// `/_admin/*` surface that creates tenants, users, access keys, buckets and
// bucket policies.
//
// It deliberately does not do S3 data operations. Use aws-sdk-go-v2 (or
// mountpoint-s3, s3fs, rclone …) for those, pointed at the same endpoint with
// a credential this package mints. See ProvisionWorkspace for the handoff.
//
// Requests are signed with SigV4 using the standard library only, so adding
// this package to a CSI driver or an operator pulls in no dependencies.
package objectio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config configures a Client. Endpoint, AccessKey and SecretKey are required.
type Config struct {
	// Endpoint is the gateway base URL, e.g. "https://s3.example.com".
	Endpoint string
	// AccessKey and SecretKey must be an *unscoped* credential: a key carrying
	// a bucket or prefix scope is refused on the management API by design, so
	// that a credential handed to a workload can never mint itself a wider one.
	AccessKey string
	SecretKey string
	// Region defaults to "us-east-1". It only has to match what the gateway
	// was started with; ObjectIO is not multi-region here.
	Region string
	// HTTPClient defaults to a client with a 30s timeout.
	HTTPClient *http.Client
}

// Client talks to the ObjectIO management API.
type Client struct {
	endpoint   string
	accessKey  string
	secretKey  string
	region     string
	httpClient *http.Client
	// now is overridable so signing can be tested against a fixed timestamp.
	now func() time.Time
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("objectio: Endpoint is required")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("objectio: AccessKey and SecretKey are required")
	}
	if _, err := url.Parse(cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("objectio: bad Endpoint %q: %w", cfg.Endpoint, err)
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		endpoint:   strings.TrimRight(cfg.Endpoint, "/"),
		accessKey:  cfg.AccessKey,
		secretKey:  cfg.SecretKey,
		region:     region,
		httpClient: hc,
		now:        time.Now,
	}, nil
}

// APIError is returned for any non-2xx response.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	// Message is the server's body, trimmed. The management API answers in
	// plain text for denials ("This access key is scoped to a bucket…") and
	// JSON for handler errors, so this is whatever it sent.
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("objectio: %s %s: %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
}

// IsNotFound reports whether err is a 404. Useful for make-if-absent flows.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusNotFound
}

// IsForbidden reports whether err is a 403 — the caller is authenticated but
// not permitted. The usual cause on this API is a scoped credential.
func IsForbidden(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusForbidden
}

// IsAlreadyExists reports whether err is the server refusing to create
// something that is already there. The management API answers 400 for this,
// so the status alone is not enough to tell it from a malformed request.
func IsAlreadyExists(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != http.StatusBadRequest {
		return false
	}
	m := strings.ToLower(ae.Message)
	return strings.Contains(m, "already exists") || strings.Contains(m, "alreadyexists")
}

// do signs and sends a request. `in` is marshalled as JSON when non-nil;
// `out` is unmarshalled from the response when non-nil.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		body, err = json.Marshal(in)
		if err != nil {
			return fmt.Errorf("objectio: encoding request: %w", err)
		}
	}

	u := c.endpoint + escapePath(path)
	if len(query) > 0 {
		u += "?" + canonicalQuery(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("objectio: building request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	sign(req, c.accessKey, c.secretKey, c.region, body, c.now())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("objectio: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	// Cap what an error body can cost us; a misrouted request can return a
	// whole HTML page.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &APIError{
			StatusCode: resp.StatusCode,
			Method:     method,
			Path:       path,
			Message:    strings.TrimSpace(string(raw)),
		}
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("objectio: decoding %s %s: %w", method, path, err)
	}
	return nil
}
