package objectio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ---------------------------------------------------------------------------
// Stored configuration
// ---------------------------------------------------------------------------

// ConfigEntry is one key of the cluster's stored configuration.
type ConfigEntry struct {
	// Key is hierarchical, e.g. "identity/openid/keycloak".
	Key string `json:"key"`
	// Value is the stored JSON document. A value that is not JSON comes back
	// as a base64 string. An OIDC provider's client_secret is redacted to
	// "********".
	Value     json.RawMessage `json:"value"`
	UpdatedAt uint64          `json:"updated_at,omitempty"`
	UpdatedBy string          `json:"updated_by,omitempty"`
	// Version increases on every write.
	Version uint64 `json:"version"`
}

// ListConfig returns the stored configuration under prefix ("" for all).
// System admin; a tenant admin sees only its own tenant's OIDC provider.
func (c *Client) ListConfig(ctx context.Context, prefix string) ([]ConfigEntry, error) {
	var q url.Values
	if prefix != "" {
		q = url.Values{"prefix": {prefix}}
	}
	var out []ConfigEntry
	if err := c.do(ctx, "GET", "/_admin/config", q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetConfig returns one key; a missing key is a 404 (IsNotFound).
func (c *Client) GetConfig(ctx context.Context, key string) (*ConfigEntry, error) {
	var out ConfigEntry
	if err := c.do(ctx, "GET", "/_admin/config/"+key, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetConfig writes a key. value must be JSON. The returned entry carries
// Key, Value and Version.
func (c *Client) SetConfig(ctx context.Context, key string, value json.RawMessage) (*ConfigEntry, error) {
	if !json.Valid(value) {
		return nil, fmt.Errorf("objectio: config value for %q is not valid JSON", key)
	}
	var out ConfigEntry
	if err := c.do(ctx, "PUT", "/_admin/config/"+key, nil, value, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteConfig removes a key; a missing key is a 404.
func (c *Client) DeleteConfig(ctx context.Context, key string) error {
	return c.do(ctx, "DELETE", "/_admin/config/"+key, nil, nil, nil)
}

// ---------------------------------------------------------------------------
// OIDC identity providers
// ---------------------------------------------------------------------------

// oidcPrefix is where providers are stored in the configuration.
const oidcPrefix = "identity/openid/"

// redacted is what the server returns in place of a stored client secret.
const redacted = "********"

// TenantOIDCProviderName is the name of a tenant's own identity provider:
// "t-<tenant>", lowercased. A tenant admin may create and manage exactly
// this one (writing it binds the tenant to it), and it is the provider
// AssumeRoleWithWebIdentity trusts for the tenant's roles.
func TenantOIDCProviderName(tenant string) string {
	return "t-" + strings.ToLower(tenant)
}

// OIDCProvider is an identity provider's stored configuration, used for
// console sign-in and to vouch for AssumeRoleWithWebIdentity.
type OIDCProvider struct {
	// Name is the provider's name, the last part of its config key. Not part
	// of the stored document.
	Name string `json:"-"`

	IssuerURL string `json:"issuer_url"`
	ClientID  string `json:"client_id"`
	// ClientSecret is write-only: reads return "********".
	ClientSecret string `json:"client_secret,omitempty"`
	// Audience defaults to ClientID.
	Audience string `json:"audience,omitempty"`
	// Scopes is space-separated; default "openid profile email".
	Scopes string `json:"scopes,omitempty"`
	// ClaimName is the claim holding the user's groups; default "groups".
	ClaimName   string `json:"claim_name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	// SystemAdmin lets the provider sign users into system scope and vouch
	// for system roles. Only the system admin may set it.
	SystemAdmin bool `json:"system_admin,omitempty"`
	// Enabled defaults to true when nil.
	Enabled *bool `json:"enabled,omitempty"`

	// Tenancy is "single" (bound to one tenant) or "multi" (a provider like
	// Entra's common endpoint federating many upstream tenants, each
	// registered as its own tenant on first sign-in).
	Tenancy string `json:"tenancy,omitempty"`
	// TenantAdminRole is the role or group claim value that makes a user an
	// admin of its tenant.
	TenantAdminRole string `json:"tenant_admin_role,omitempty"`
	// TenantQuotaBytes is the quota a self-registered tenant starts with.
	TenantQuotaBytes uint64 `json:"tenant_quota_bytes,omitempty"`
	// AllowedTIDs restricts which upstream tenants may self-register; empty
	// admits any.
	AllowedTIDs []string `json:"allowed_tids,omitempty"`

	// Extra holds any other fields of the stored document (the console
	// keeps a few of its own), so that a read-modify-write does not drop
	// them.
	Extra map[string]json.RawMessage `json:"-"`
}

// Bool returns a pointer to b, for optional fields such as
// OIDCProvider.Enabled.
func Bool(b bool) *bool { return &b }

type oidcProviderFields OIDCProvider

// MarshalJSON writes the known fields and then Extra, known fields winning.
func (p OIDCProvider) MarshalJSON() ([]byte, error) {
	known, err := json.Marshal(oidcProviderFields(p))
	if err != nil {
		return nil, err
	}
	if len(p.Extra) == 0 {
		return known, nil
	}
	merged := map[string]json.RawMessage{}
	for k, v := range p.Extra {
		merged[k] = v
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(known, &fields); err != nil {
		return nil, err
	}
	for k, v := range fields {
		merged[k] = v
	}
	return json.Marshal(merged)
}

// UnmarshalJSON reads the known fields and keeps the rest in Extra.
func (p *OIDCProvider) UnmarshalJSON(b []byte) error {
	var known oidcProviderFields
	if err := json.Unmarshal(b, &known); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for _, k := range []string{
		"issuer_url", "client_id", "client_secret", "audience", "scopes",
		"claim_name", "display_name", "system_admin", "enabled", "tenancy",
		"tenant_admin_role", "tenant_quota_bytes", "allowed_tids",
	} {
		delete(all, k)
	}
	name := p.Name
	*p = OIDCProvider(known)
	p.Name = name
	if len(all) > 0 {
		p.Extra = all
	}
	return nil
}

func providerFromEntry(e ConfigEntry) (OIDCProvider, error) {
	var p OIDCProvider
	if err := json.Unmarshal(e.Value, &p); err != nil {
		return OIDCProvider{}, fmt.Errorf("objectio: provider %s: %w", e.Key, err)
	}
	p.Name = strings.TrimPrefix(e.Key, oidcPrefix)
	return p, nil
}

// ListOIDCProviders returns every stored identity provider (for a tenant
// admin, only its tenant's).
func (c *Client) ListOIDCProviders(ctx context.Context) ([]OIDCProvider, error) {
	entries, err := c.ListConfig(ctx, oidcPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]OIDCProvider, 0, len(entries))
	for _, e := range entries {
		p, err := providerFromEntry(e)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// GetOIDCProvider returns one provider. Its ClientSecret reads "********".
func (c *Client) GetOIDCProvider(ctx context.Context, name string) (*OIDCProvider, error) {
	e, err := c.GetConfig(ctx, oidcPrefix+name)
	if err != nil {
		return nil, err
	}
	p, err := providerFromEntry(*e)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// PutOIDCProvider creates or replaces a provider. A tenant admin may write
// only TenantOIDCProviderName(its tenant), and writing it binds the tenant
// to it.
//
// The whole document is replaced, secret included — and reads return the
// secret as "********". So a provider read with GetOIDCProvider must have
// its ClientSecret set again before it is written back; PutOIDCProvider
// refuses the redacted placeholder rather than store it as the secret.
func (c *Client) PutOIDCProvider(ctx context.Context, name string, p OIDCProvider) (*OIDCProvider, error) {
	if name == "" {
		return nil, fmt.Errorf("objectio: provider name is required")
	}
	if p.ClientSecret == redacted {
		return nil, fmt.Errorf("objectio: ClientSecret is the redacted placeholder %q; set the real secret (or \"\" for a public client)", redacted)
	}
	body, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("objectio: encoding provider: %w", err)
	}
	e, err := c.SetConfig(ctx, oidcPrefix+name, body)
	if err != nil {
		return nil, err
	}
	out, err := providerFromEntry(*e)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteOIDCProvider removes a provider, and with it the sign-ins and role
// assumptions it vouched for.
func (c *Client) DeleteOIDCProvider(ctx context.Context, name string) error {
	return c.DeleteConfig(ctx, oidcPrefix+name)
}
