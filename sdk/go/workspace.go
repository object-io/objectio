package objectio

import (
	"context"
	"fmt"
)

// Workspace is the result of ProvisionWorkspace: a bucket and the one
// credential that reaches it.
type Workspace struct {
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

// ProvisionWorkspaceInput describes one workspace.
type ProvisionWorkspaceInput struct {
	// Bucket is the workspace's bucket. One bucket per workspace is the
	// intended shape; the credential is confined to it.
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

// ProvisionWorkspace creates the bucket and mints a credential scoped to it.
//
// The credential cannot reach another workspace's bucket, and cannot be used
// against this management API at all — a scoped key is refused there — so it
// is safe to hand to a workload that should only see its own data.
//
// It is not idempotent on its own: calling it twice with the same bucket
// fails on the create. Use IsAlreadyExists to make it make-if-absent, or call
// CreateAccessKey directly when you only want to rotate the credential.
func (c *Client) ProvisionWorkspace(ctx context.Context, in ProvisionWorkspaceInput) (*Workspace, error) {
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

	return &Workspace{
		Bucket:      in.Bucket,
		Tenant:      in.Tenant,
		AccessKeyID: key.AccessKeyID,
		SecretKey:   key.SecretKey,
		Scope:       key.Scope,
		ReadOnly:    in.ReadOnly,
	}, nil
}

// DeprovisionWorkspace revokes every key scoped to the workspace's bucket and
// then deletes the bucket. The bucket must already be empty — this does not
// delete objects, deliberately: losing a workspace's data should take more
// than one call.
func (c *Client) DeprovisionWorkspace(ctx context.Context, provisionerUserID, bucket string) error {
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

// RotateWorkspaceKey mints a fresh credential for a workspace and returns it.
// The old key keeps working until you delete it, so a rollout can overlap.
func (c *Client) RotateWorkspaceKey(ctx context.Context, provisionerUserID, bucket string, readOnly bool) (*Workspace, error) {
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
	return &Workspace{
		Bucket:      bucket,
		AccessKeyID: key.AccessKeyID,
		SecretKey:   key.SecretKey,
		Scope:       key.Scope,
		ReadOnly:    readOnly,
	}, nil
}
