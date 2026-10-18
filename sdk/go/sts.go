package objectio

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// AssumeRoleWithWebIdentityInput is an OIDC token to exchange for a role's
// temporary credentials.
type AssumeRoleWithWebIdentityInput struct {
	// RoleArn is the role's ARN, arn:obio:iam::<tenant>:role/<name> (or
	// ::objectio: for a system role; arn:aws: is accepted too).
	RoleArn string
	// WebIdentityToken is the OIDC ID token. It is the only proof of
	// identity in the request.
	WebIdentityToken string
	// RoleSessionName names the session in the assumed-role ARN and in
	// logs: 2–64 characters of [A-Za-z0-9_+=,.@-].
	RoleSessionName string
	// DurationSeconds defaults to an hour (or the role's limit, if lower).
	// It must be at least 900 and at most the role's MaxSessionSeconds.
	DurationSeconds int
}

// Credentials are temporary credentials for an assumed role. All three
// parts are needed: an S3 client signs with AccessKeyID/SecretAccessKey and
// sends SessionToken as X-Amz-Security-Token.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	// AssumedRoleArn is arn:obio:sts::<tenant>:assumed-role/<role>/<session>.
	AssumedRoleArn string
}

type assumeRoleWithWebIdentityResponse struct {
	Result struct {
		Credentials struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"Credentials"`
		AssumedRoleUser struct {
			Arn string `xml:"Arn"`
		} `xml:"AssumedRoleUser"`
	} `xml:"AssumeRoleWithWebIdentityResult"`
}

// AssumeRoleWithWebIdentity exchanges an OIDC token for a role's temporary
// credentials, through the STS endpoint the gateway serves on its S3 port.
//
// The request is unsigned — the token is the proof — so this works on a
// Client built with an Endpoint alone, which is the point: a workload
// holding only its identity token has no key to sign with yet.
//
//	sts, _ := objectio.New(objectio.Config{Endpoint: endpoint})
//	creds, err := sts.AssumeRoleWithWebIdentity(ctx, objectio.AssumeRoleWithWebIdentityInput{...})
//
// Which identity providers may vouch for a role depends on its scope: a
// tenant's role trusts only that tenant's own provider
// (TenantOIDCProviderName), a system role only the operator's. STS errors
// come back as an *APIError whose Code is the STS code — AccessDenied,
// InvalidIdentityToken, ExpiredTokenException, ValidationError, ….
func (c *Client) AssumeRoleWithWebIdentity(ctx context.Context, in AssumeRoleWithWebIdentityInput) (*Credentials, error) {
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {in.RoleArn},
		"WebIdentityToken": {in.WebIdentityToken},
		"RoleSessionName":  {in.RoleSessionName},
	}
	if in.DurationSeconds != 0 {
		form.Set("DurationSeconds", strconv.Itoa(in.DurationSeconds))
	}
	// Unsigned on purpose: the gateway routes a POST to "/" with no
	// Authorization header to STS, and anything signed to S3.
	raw, err := c.send(ctx, "POST", "/", nil, []byte(form.Encode()),
		"application/x-www-form-urlencoded", false)
	if err != nil {
		return nil, err
	}
	var resp assumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("objectio: decoding STS response: %w", err)
	}
	cr := resp.Result.Credentials
	if cr.AccessKeyID == "" {
		return nil, fmt.Errorf("objectio: STS response carried no credentials")
	}
	out := &Credentials{
		AccessKeyID:     cr.AccessKeyID,
		SecretAccessKey: cr.SecretAccessKey,
		SessionToken:    cr.SessionToken,
		AssumedRoleArn:  resp.Result.AssumedRoleUser.Arn,
	}
	if cr.Expiration != "" {
		exp, err := time.Parse(time.RFC3339, cr.Expiration)
		if err != nil {
			return nil, fmt.Errorf("objectio: STS Expiration %q: %w", cr.Expiration, err)
		}
		out.Expiration = exp
	}
	return out, nil
}
