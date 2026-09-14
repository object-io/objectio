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

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

// Bucket as the management API reports it.
type Bucket struct {
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at,omitempty"`
	// Owner is the creator's user_id. With no policy attached, ObjectIO
	// authorizes on ownership alone — so this decides who can reach the
	// bucket by default.
	Owner      string `json:"owner,omitempty"`
	Versioning int    `json:"versioning,omitempty"`
	Pool       string `json:"pool,omitempty"`
	Tenant     string `json:"tenant,omitempty"`
}

// CreateBucket creates a bucket. Pass tenant "" to use the caller's own
// tenant; a tenant admin cannot create outside its tenant.
//
// The caller becomes the owner, which matters: with no policy attached,
// ownership is what grants access.
func (c *Client) CreateBucket(ctx context.Context, name, tenant string) error {
	body := map[string]string{"name": name}
	if tenant != "" {
		body["tenant"] = tenant
	}
	return c.do(ctx, "POST", "/_admin/buckets", nil, body, nil)
}

// ListBuckets returns the buckets the caller can see.
func (c *Client) ListBuckets(ctx context.Context) ([]Bucket, error) {
	var out struct {
		Buckets []Bucket `json:"buckets"`
	}
	if err := c.do(ctx, "GET", "/_admin/buckets", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Buckets, nil
}

// DeleteBucket removes an empty bucket.
func (c *Client) DeleteBucket(ctx context.Context, name string) error {
	return c.do(ctx, "DELETE", "/_admin/buckets/"+name, nil, nil, nil)
}

// SetBucketOwner reassigns ownership. Use it to backfill a bucket created
// before the creator was recorded, or to hand a bucket to another identity.
func (c *Client) SetBucketOwner(ctx context.Context, bucket, ownerUserID string) error {
	return c.do(ctx, "PUT", "/_admin/buckets/"+bucket+"/owner",
		nil, map[string]string{"owner": ownerUserID}, nil)
}

// GetBucketPolicy returns the attached policy, or nil when there is none.
//
// No policy does not mean open: ObjectIO then falls back to owner-only.
func (c *Client) GetBucketPolicy(ctx context.Context, bucket string) (json.RawMessage, error) {
	var out struct {
		HasPolicy bool            `json:"has_policy"`
		Policy    json.RawMessage `json:"policy"`
	}
	if err := c.do(ctx, "GET", "/_admin/buckets/"+bucket+"/policy", nil, nil, &out); err != nil {
		return nil, err
	}
	if !out.HasPolicy {
		return nil, nil
	}
	return out.Policy, nil
}

// PutBucketPolicy attaches a policy document. Needed only when an identity
// other than the owner must reach the bucket — a workspace's own users, say,
// rather than the provisioner that created it.
//
// Principals are ARNs under {"OBIO": [...]}; {"AWS": [...]} is accepted as a
// synonym.
func (c *Client) PutBucketPolicy(ctx context.Context, bucket string, policy json.RawMessage) error {
	return c.do(ctx, "PUT", "/_admin/buckets/"+bucket+"/policy", nil, policy, nil)
}

// DeleteBucketPolicy detaches the policy, returning the bucket to owner-only.
func (c *Client) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	return c.do(ctx, "DELETE", "/_admin/buckets/"+bucket+"/policy", nil, nil, nil)
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
