package objectio

import (
	"context"
	"encoding/json"
	"fmt"
)

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
	return c.CreateBucketInPool(ctx, name, tenant, "")
}

// CreateBucketInPool creates a bucket whose data goes to pool. Empty pool
// means the tenant's default pool (or the cluster's default placement). A
// tenant may use only its default pool and its allowed pools; the pool is
// fixed for the bucket's life.
func (c *Client) CreateBucketInPool(ctx context.Context, name, tenant, pool string) error {
	body := map[string]string{"name": name}
	if tenant != "" {
		body["tenant"] = tenant
	}
	if pool != "" {
		body["pool"] = pool
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
// other than the owner must reach the bucket — a team's own users, say,
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
// Deduplication
// ---------------------------------------------------------------------------

// DedupPolicy is a deduplication setting at one level. Mode is "off",
// "dry-run" or "on"; Scope is "bucket", "tenant" or "cluster". Either may be
// left empty to inherit the next level's value.
type DedupPolicy struct {
	Mode  string `json:"mode,omitempty"`
	Scope string `json:"scope,omitempty"`
}

// GetBucketDedup returns the bucket's dedup policy at every level and what
// it resolves to, as the server reports it: {"bucket", "tenant",
// "tenant_name", "cluster", "effective": {"mode", "scope", "mode_from",
// "scope_from"}}. Raw JSON: it is a report to read, not an object to edit.
func (c *Client) GetBucketDedup(ctx context.Context, bucket string) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, "GET", "/_admin/buckets/"+bucket+"/dedup", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SetBucketDedup sets the bucket's own dedup policy and returns the resolved
// report, as GetBucketDedup.
func (c *Client) SetBucketDedup(ctx context.Context, bucket string, p DedupPolicy) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, "PUT", "/_admin/buckets/"+bucket+"/dedup", nil, p, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteBucketDedup drops the bucket's own policy so it inherits everything,
// and returns the resolved report.
func (c *Client) DeleteBucketDedup(ctx context.Context, bucket string) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, "DELETE", "/_admin/buckets/"+bucket+"/dedup", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Provisioning: a bucket and the one credential that reaches it
// ---------------------------------------------------------------------------

// BucketAccess is the result of ProvisionBucket and RotateBucketKey: a bucket
// and the one credential that reaches it.
type BucketAccess struct {
	Bucket string
	Tenant string
	// AccessKeyID and SecretKey are confined to Bucket. Hand them to an S3
	// client — aws-sdk-go-v2, mountpoint-s3, s3fs, rclone — pointed at the
	// same endpoint.
	AccessKeyID string
	SecretKey   string
	// Scope is the confinement as stored, e.g. "s3://ws-1/".
	Scope string
	// ReadOnly reflects the operation the key was minted with.
	ReadOnly bool
}

// ProvisionBucketInput describes one bucket to provision.
type ProvisionBucketInput struct {
	// Bucket to create. One bucket per consumer (an app, a team, a
	// project) is the intended shape; the credential is confined to it.
	Bucket string
	// Tenant to create it in. Empty uses the caller's own tenant, which is
	// what a tenant-admin provisioner wants.
	Tenant string
	// ProvisionerUserID is the user the credential is minted on — normally the
	// provisioner's own user, the one whose credential this client holds.
	//
	// Minting on the provisioner is what makes this two calls instead of four:
	// the provisioner owns the bucket it just created, so ownership already
	// grants access and no bucket policy is needed. The scope then narrows
	// that ownership down to this one bucket.
	ProvisionerUserID string
	// ReadOnly mints a key that refuses PUT, POST and DELETE.
	ReadOnly bool
	// Prefix optionally confines the credential further, to
	// "s3://<bucket>/<prefix>" rather than the whole bucket. Must end in "/".
	Prefix string
}

// ProvisionBucket creates the bucket and mints a credential scoped to it.
//
// The credential cannot reach another provisioned bucket, and cannot be used
// against this management API at all — a scoped key is refused there — so it
// is safe to hand to a workload that should only see its own data.
//
// It is not idempotent on its own: calling it twice with the same bucket
// fails on the create. Use IsAlreadyExists to make it make-if-absent, or call
// CreateAccessKey directly when you only want to rotate the credential.
func (c *Client) ProvisionBucket(ctx context.Context, in ProvisionBucketInput) (*BucketAccess, error) {
	if in.Bucket == "" {
		return nil, fmt.Errorf("objectio: Bucket is required")
	}
	if in.ProvisionerUserID == "" {
		return nil, fmt.Errorf("objectio: ProvisionerUserID is required")
	}
	if in.Prefix != "" && in.Prefix[len(in.Prefix)-1] != '/' {
		return nil, fmt.Errorf("objectio: Prefix %q must end in /", in.Prefix)
	}

	if err := c.CreateBucket(ctx, in.Bucket, in.Tenant); err != nil {
		return nil, err
	}

	scope := "s3://" + in.Bucket + "/" + in.Prefix
	op := ReadWrite
	if in.ReadOnly {
		op = ReadOnly
	}
	key, err := c.CreateAccessKey(ctx, in.ProvisionerUserID, CreateAccessKeyInput{
		Scope:     scope,
		Operation: op,
	})
	if err != nil {
		// The bucket exists but has no credential. Leave it: deleting it here
		// would destroy a bucket that may already be taking writes from an
		// earlier run, and the caller can retry the key on its own.
		return nil, fmt.Errorf("objectio: bucket %q created but minting its key failed: %w", in.Bucket, err)
	}

	return &BucketAccess{
		Bucket:      in.Bucket,
		Tenant:      in.Tenant,
		AccessKeyID: key.AccessKeyID,
		SecretKey:   key.SecretKey,
		Scope:       key.Scope,
		ReadOnly:    in.ReadOnly,
	}, nil
}

// DeprovisionBucket revokes every key on provisionerUserID scoped to the
// bucket and then deletes the bucket. The bucket must already be empty —
// this does not delete objects, deliberately: losing a bucket's data should
// take more than one call.
func (c *Client) DeprovisionBucket(ctx context.Context, provisionerUserID, bucket string) error {
	keys, err := c.ListAccessKeys(ctx, provisionerUserID)
	if err != nil {
		return err
	}
	want := "s3://" + bucket + "/"
	for _, k := range keys {
		if k.Scope == want || (len(k.Scope) > len(want) && k.Scope[:len(want)] == want) {
			if err := c.DeleteAccessKey(ctx, k.AccessKeyID); err != nil {
				return fmt.Errorf("objectio: revoking %s: %w", k.AccessKeyID, err)
			}
		}
	}
	return c.DeleteBucket(ctx, bucket)
}

// RotateBucketKey mints a fresh credential scoped to a provisioned bucket and
// returns it. The old key keeps working until you delete or deactivate it,
// so a rollout can overlap.
func (c *Client) RotateBucketKey(ctx context.Context, provisionerUserID, bucket string, readOnly bool) (*BucketAccess, error) {
	op := ReadWrite
	if readOnly {
		op = ReadOnly
	}
	key, err := c.CreateAccessKey(ctx, provisionerUserID, CreateAccessKeyInput{
		Scope:     "s3://" + bucket + "/",
		Operation: op,
	})
	if err != nil {
		return nil, err
	}
	return &BucketAccess{
		Bucket:      bucket,
		AccessKeyID: key.AccessKeyID,
		SecretKey:   key.SecretKey,
		Scope:       key.Scope,
		ReadOnly:    readOnly,
	}, nil
}
