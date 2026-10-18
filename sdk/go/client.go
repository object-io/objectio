// Package objectio is a client for the ObjectIO **management API** — the
// `/_admin/*` surface that creates tenants, users, access keys, buckets and
// bucket policies.
//
// It deliberately does not do S3 data operations. Use aws-sdk-go-v2 (or
// mountpoint-s3, s3fs, rclone …) for those, pointed at the same endpoint with
// a credential this package mints. See ProvisionBucket for the handoff.
//
// Requests are signed with SigV4 using the standard library only, so adding
// this package to a CSI driver or an operator pulls in no dependencies.
package objectio

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config configures a Client. Endpoint is required; AccessKey and SecretKey
// are required for everything except AssumeRoleWithWebIdentity.
type Config struct {
	// Endpoint is the gateway base URL, e.g. "https://s3.example.com".
	Endpoint string
	// AccessKey and SecretKey must be an *unscoped* credential: a key carrying
	// a bucket or prefix scope is refused on the management API by design, so
	// that a credential handed to a workload can never mint itself a wider one.
	//
	// Leave both empty for a client that only calls AssumeRoleWithWebIdentity:
	// that request is unsigned (the web identity token is the proof), and a
	// workload exchanging its token has no key to sign with yet. Every other
	// method on such a client returns ErrNoCredentials without sending.
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
	// Both or neither: one without the other is a misconfiguration, not an
	// STS-only client.
	if (cfg.AccessKey == "") != (cfg.SecretKey == "") {
		return nil, fmt.Errorf("objectio: AccessKey and SecretKey must be set together")
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

// ErrNoCredentials is returned by a signed call on a client built without
// AccessKey and SecretKey.
var ErrNoCredentials = errors.New("objectio: this client has no AccessKey/SecretKey; only AssumeRoleWithWebIdentity works without them")

// APIError is returned for any non-2xx response.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	// Code is the error code of an XML error document — what the S3 calls
	// (public access block, policy status) and STS answer with, e.g.
	// "NoSuchPublicAccessBlockConfiguration" or "InvalidIdentityToken". Empty
	// for the management API's plain-text and JSON errors.
	Code string
	// Message is the server's body, trimmed. The management API answers in
	// plain text for denials ("This access key is scoped to a bucket…") and
	// JSON for handler errors, so this is whatever it sent. For an XML error
	// document it is the document's <Message>.
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("objectio: %s %s: %d %s: %s", e.Method, e.Path, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("objectio: %s %s: %d: %s", e.Method, e.Path, e.StatusCode, e.Message)
}

// xmlError is the shape both S3 (<Error>) and STS (<ErrorResponse><Error>)
// use; only Code and Message matter here.
type xmlError struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
	Inner   *struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// newAPIError builds the error for a non-2xx answer, lifting Code and
// Message out of an XML error document when that is what came back.
func newAPIError(status int, method, path string, raw []byte) *APIError {
	e := &APIError{StatusCode: status, Method: method, Path: path, Message: strings.TrimSpace(string(raw))}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '<' {
		return e
	}
	var x xmlError
	if xml.Unmarshal(trimmed, &x) != nil {
		return e
	}
	code, msg := x.Code, x.Message
	if x.Inner != nil && x.Inner.Code != "" {
		code, msg = x.Inner.Code, x.Inner.Message
	}
	if code != "" {
		e.Code, e.Message = code, msg
	}
	return e
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
// something that is already there.
//
// 409 is the clean answer, but the tenant and bucket creates predate that and
// still return 400 with the reason in the message — so accept either, rather
// than making a caller's idempotency depend on which endpoint it called.
func IsAlreadyExists(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	if ae.StatusCode == http.StatusConflict {
		return true
	}
	if ae.StatusCode != http.StatusBadRequest {
		return false
	}
	m := strings.ToLower(ae.Message)
	return strings.Contains(m, "already exists") || strings.Contains(m, "alreadyexists")
}

// do signs and sends a JSON request. `in` is marshalled as JSON when non-nil;
// `out` is unmarshalled from the response when non-nil.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body []byte
	contentType := ""
	if in != nil {
		var err error
		// A json.RawMessage is sent as is; anything else is marshalled.
		if raw, ok := in.(json.RawMessage); ok {
			body = raw
		} else if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("objectio: encoding request: %w", err)
		}
		contentType = "application/json"
	}
	raw, err := c.send(ctx, method, path, query, body, contentType, true)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("objectio: decoding %s %s: %w", method, path, err)
	}
	return nil
}

// send performs one request and returns the response body, or an *APIError
// for a non-2xx answer. `signed` false sends it without an Authorization
// header at all — which is what routes a POST to "/" to STS rather than S3.
func (c *Client) send(ctx context.Context, method, path string, query url.Values, body []byte, contentType string, signed bool) ([]byte, error) {
	if signed && c.accessKey == "" {
		return nil, ErrNoCredentials
	}
	u := c.endpoint + escapePath(path)
	if len(query) > 0 {
		u += "?" + canonicalQuery(query)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("objectio: building request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if signed {
		sign(req, c.accessKey, c.secretKey, c.region, body, c.now())
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("objectio: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	// Cap what a body can cost us; a misrouted request can return a whole
	// HTML page.
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, newAPIError(resp.StatusCode, method, path, raw)
	}
	return raw, nil
}
