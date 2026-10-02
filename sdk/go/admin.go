package objectio

import (
	"context"
	"encoding/json"
)

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

// Tenant is a tenancy boundary: its buckets, users and quotas are its own, and
// a credential belonging to one tenant cannot act on another.
type Tenant struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"display_name,omitempty"`
	DefaultPool  string            `json:"default_pool,omitempty"`
	AllowedPools []string          `json:"allowed_pools,omitempty"`
	QuotaBytes   uint64            `json:"quota_bytes,omitempty"`
	QuotaBuckets uint64            `json:"quota_buckets,omitempty"`
	QuotaObjects uint64            `json:"quota_objects,omitempty"`
	AdminUsers   []string          `json:"admin_users,omitempty"`
	OIDCProvider string            `json:"oidc_provider,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Enabled      bool              `json:"enabled"`
	CreatedAt    int64             `json:"created_at,omitempty"`
	UpdatedAt    int64             `json:"updated_at,omitempty"`
	// Dedup is the tenant's deduplication policy ({"mode", "scope"}) or null
	// to inherit. Kept as raw JSON so that UpdateTenant sends back exactly
	// what it read: the server replaces the whole tenant, and a field left
	// out resets to inherit.
	Dedup json.RawMessage `json:"dedup,omitempty"`
}

// CreateTenant creates a tenant. System admin only.
func (c *Client) CreateTenant(ctx context.Context, t Tenant) (*Tenant, error) {
	var out Tenant
	if err := c.do(ctx, "POST", "/_admin/tenants", nil, t, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTenant returns one tenant.
func (c *Client) GetTenant(ctx context.Context, name string) (*Tenant, error) {
	var out Tenant
	if err := c.do(ctx, "GET", "/_admin/tenants/"+name, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListTenants returns every tenant the caller can see.
func (c *Client) ListTenants(ctx context.Context) ([]Tenant, error) {
	// The endpoint answers with a bare array on some builds and {"tenants":[…]}
	// on others; accept both rather than breaking on a version skew.
	var raw json.RawMessage
	if err := c.do(ctx, "GET", "/_admin/tenants", nil, nil, &raw); err != nil {
		return nil, err
	}
	return decodeList[Tenant](raw, "tenants")
}

// UpdateTenant changes a tenant by reading it, applying update, and writing
// the whole thing back. System admin only.
//
// It is read-modify-write rather than a partial PUT because the server
// replaces the tenant wholesale: any field a PUT leaves out — admins,
// quotas, labels, the dedup policy — is reset, and `enabled` defaults to
// true. Taking a function keeps a caller from having to restate every field
// to change one. The name cannot be changed; update's edits to it are
// ignored.
//
// Two concurrent updates are not merged: the server compares against what
// it had and answers 409 to the loser (IsAlreadyExists does not match that;
// check the StatusCode), which can simply call again.
func (c *Client) UpdateTenant(ctx context.Context, name string, update func(*Tenant)) (*Tenant, error) {
	t, err := c.GetTenant(ctx, name)
	if err != nil {
		return nil, err
	}
	update(t)
	t.Name = name
	var out Tenant
	if err := c.do(ctx, "PUT", "/_admin/tenants/"+name, nil, t, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteTenant removes a tenant. Its buckets must be gone first.
func (c *Client) DeleteTenant(ctx context.Context, name string) error {
	return c.do(ctx, "DELETE", "/_admin/tenants/"+name, nil, nil, nil)
}

// AddTenantAdmin grants a user administration of its own tenant: it may then
// create buckets, users and access keys inside that tenant and nowhere else.
// This is what turns a plain user into a provisioner.
func (c *Client) AddTenantAdmin(ctx context.Context, tenant, userID string) error {
	return c.do(ctx, "POST", "/_admin/tenants/"+tenant+"/admins",
		nil, map[string]string{"user_id": userID}, nil)
}

// RemoveTenantAdmin revokes it again.
func (c *Client) RemoveTenantAdmin(ctx context.Context, tenant, user string) error {
	return c.do(ctx, "DELETE", "/_admin/tenants/"+tenant+"/admins/"+user, nil, nil, nil)
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// User is an IAM identity. Access keys belong to a user and inherit its
// tenant; a user belongs to exactly one tenant (empty means system scope).
type User struct {
	UserID      string `json:"user_id"`
	DisplayName string `json:"display_name"`
	ARN         string `json:"arn,omitempty"`
	Status      string `json:"status,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
	Email       string `json:"email,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
}

// CreateUser creates a user. Pass tenant "" for a system-scope user, which
// requires the system admin.
func (c *Client) CreateUser(ctx context.Context, displayName, tenant string) (*User, error) {
	var out User
	body := map[string]string{"display_name": displayName, "tenant": tenant}
	if err := c.do(ctx, "POST", "/_admin/users", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListUsers returns the users the caller can see: every user for the system
// admin, and only its own tenant's for a tenant admin.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	var out struct {
		Users []User `json:"users"`
	}
	if err := c.do(ctx, "GET", "/_admin/users", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

// DeleteUser removes a user and its access keys.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	return c.do(ctx, "DELETE", "/_admin/users/"+userID, nil, nil, nil)
}

// GetUser returns one user. A tenant admin may read its own tenant's users.
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	var out User
	if err := c.do(ctx, "GET", "/_admin/users/"+userID, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// User statuses, as UpdateUser takes and User.Status reports them.
const (
	UserActive    = "active"
	UserSuspended = "suspended"
)

// UserUpdate is a partial change to a user: nil fields are left as they are.
type UserUpdate struct {
	DisplayName *string `json:"display_name,omitempty"`
	Email       *string `json:"email,omitempty"`
	// Status is UserActive or UserSuspended.
	Status *string `json:"status,omitempty"`
}

// UpdateUser changes a user's display name, email or status and returns the
// result.
func (c *Client) UpdateUser(ctx context.Context, userID string, in UserUpdate) (*User, error) {
	var out User
	if err := c.do(ctx, "PUT", "/_admin/users/"+userID, nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SuspendUser refuses every key the user holds without deleting anything,
// so ActivateUser restores it exactly. It holds at once on the gateway that
// made the change and within 15 seconds on the others (their credential
// cache). The server refuses to let a caller suspend itself.
func (c *Client) SuspendUser(ctx context.Context, userID string) (*User, error) {
	s := UserSuspended
	return c.UpdateUser(ctx, userID, UserUpdate{Status: &s})
}

// ActivateUser lifts a suspension.
func (c *Client) ActivateUser(ctx context.Context, userID string) (*User, error) {
	s := UserActive
	return c.UpdateUser(ctx, userID, UserUpdate{Status: &s})
}

// ---------------------------------------------------------------------------
// Access keys
// ---------------------------------------------------------------------------

// Operation is what an access key may do. It narrows the user's rights; it
// never widens them.
type Operation string

const (
	// ReadWrite is the default when unset.
	ReadWrite Operation = "RW"
	// ReadOnly refuses PUT, POST and DELETE.
	ReadOnly Operation = "R"
)

// AccessKey is a credential. SecretKey is returned only by CreateAccessKey —
// it is never readable again, so persist it at once or lose it.
type AccessKey struct {
	AccessKeyID string `json:"access_key_id"`
	SecretKey   string `json:"secret_access_key,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	Status      string `json:"status,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
	// Scope confines the key to one bucket or prefix, as "s3://bucket/" or
	// "s3://bucket/prefix/". Empty means unscoped.
	Scope string `json:"scope,omitempty"`
	// Operation is "READ" or "READ_WRITE" as returned by the server.
	Operation string `json:"operation,omitempty"`
}

// Scoped reports whether the key is confined to a bucket or prefix. A scoped
// key cannot be used against this management API — that is what stops a
// credential handed to a workload from minting itself a wider one.
func (k AccessKey) Scoped() bool { return k.Scope != "" }

// CreateAccessKeyInput asks for a new key on a user.
type CreateAccessKeyInput struct {
	// Scope confines the key, e.g. "s3://ws-1/". Leave empty for a key with
	// the user's full rights — which, for a tenant admin, includes this API.
	Scope string `json:"scope,omitempty"`
	// Operation defaults to ReadWrite.
	Operation Operation `json:"operation,omitempty"`
}

// CreateAccessKey mints a key for a user. The returned SecretKey is the only
// copy.
func (c *Client) CreateAccessKey(ctx context.Context, userID string, in CreateAccessKeyInput) (*AccessKey, error) {
	var out AccessKey
	if err := c.do(ctx, "POST", "/_admin/users/"+userID+"/access-keys", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAccessKeys returns a user's keys, without their secrets.
func (c *Client) ListAccessKeys(ctx context.Context, userID string) ([]AccessKey, error) {
	var raw json.RawMessage
	if err := c.do(ctx, "GET", "/_admin/users/"+userID+"/access-keys", nil, nil, &raw); err != nil {
		return nil, err
	}
	return decodeList[AccessKey](raw, "access_keys")
}

// DeleteAccessKey revokes a key. This is the rotation primitive: mint the
// replacement, roll it out, then delete the old one.
func (c *Client) DeleteAccessKey(ctx context.Context, accessKeyID string) error {
	return c.do(ctx, "DELETE", "/_admin/access-keys/"+accessKeyID, nil, nil, nil)
}

// Access key statuses, as UpdateAccessKey takes and AccessKey.Status
// reports them.
const (
	KeyActive   = "active"
	KeyInactive = "inactive"
)

// AccessKeyUpdate is a change to an access key. Status is the only thing
// that can change; the scope and operation are fixed when a key is minted.
type AccessKeyUpdate struct {
	// Status is KeyActive or KeyInactive.
	Status string `json:"status"`
}

// UpdateAccessKey changes a key's status. The returned AccessKey carries
// AccessKeyID, UserID and Status only.
func (c *Client) UpdateAccessKey(ctx context.Context, accessKeyID string, in AccessKeyUpdate) (*AccessKey, error) {
	var out AccessKey
	if err := c.do(ctx, "PUT", "/_admin/access-keys/"+accessKeyID, nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeactivateAccessKey stops a key working without deleting it — the
// reversible half of revocation, for a key suspected leaked while the
// investigation runs. The server refuses to deactivate the key the request
// is signed with.
func (c *Client) DeactivateAccessKey(ctx context.Context, accessKeyID string) (*AccessKey, error) {
	return c.UpdateAccessKey(ctx, accessKeyID, AccessKeyUpdate{Status: KeyInactive})
}

// ActivateAccessKey reverses DeactivateAccessKey.
//
// Only the system admin can reactivate a key: the server finds a key's owner
// through the lookup authentication uses, which does not return inactive
// keys, so it cannot tell which tenant an inactive key belongs to and falls
// back to requiring the system admin.
func (c *Client) ActivateAccessKey(ctx context.Context, accessKeyID string) (*AccessKey, error) {
	return c.UpdateAccessKey(ctx, accessKeyID, AccessKeyUpdate{Status: KeyActive})
}

// ---------------------------------------------------------------------------

// decodeList accepts either a bare JSON array or {"<key>": [...]}. Several
// management endpoints differ on this between builds.
func decodeList[T any](raw json.RawMessage, key string) ([]T, error) {
	var direct []T
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct, nil
	}
	wrapped := map[string][]T{}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	return wrapped[key], nil
}
