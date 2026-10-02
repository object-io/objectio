package objectio

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
)

// Block Public Access, as S3 has it, at three levels: a bucket, its tenant
// (S3's account level) and the whole cluster. A flag set at any level holds
// for the bucket — a tenant cannot loosen what the cluster sets, nor a
// bucket what its tenant sets.
//
// New buckets start with every flag set, as S3's have since 2023, unless the
// operator turns that off with PutPublicAccessBlock(ctx, "", …,
// Bool(false)).

// PublicAccessBlock is S3's four flags, under S3's names.
type PublicAccessBlock struct {
	// BlockPublicAcls and IgnorePublicAcls are kept and reported. ACLs are
	// owner-enforced in ObjectIO, so no ACL can grant public access in the
	// first place; both hold by construction.
	BlockPublicAcls  bool `json:"BlockPublicAcls" xml:"BlockPublicAcls"`
	IgnorePublicAcls bool `json:"IgnorePublicAcls" xml:"IgnorePublicAcls"`
	// BlockPublicPolicy refuses a bucket policy that would make the bucket
	// public.
	BlockPublicPolicy bool `json:"BlockPublicPolicy" xml:"BlockPublicPolicy"`
	// RestrictPublicBuckets makes a public policy already in place grant
	// nothing to anonymous callers, or to callers outside the bucket's
	// tenant.
	RestrictPublicBuckets bool `json:"RestrictPublicBuckets" xml:"RestrictPublicBuckets"`
}

// BlockAll is every flag set — what a new bucket starts with.
var BlockAll = PublicAccessBlock{
	BlockPublicAcls:       true,
	IgnorePublicAcls:      true,
	BlockPublicPolicy:     true,
	RestrictPublicBuckets: true,
}

// AccountPublicAccessBlock is a tenant's or the cluster's block.
type AccountPublicAccessBlock struct {
	PublicAccessBlock
	// Tenant is the tenant it belongs to; empty for the cluster.
	Tenant string `json:"tenant"`
	// NewBucketsBlocked is set for the cluster only: whether new buckets
	// start with BlockAll as their own block.
	NewBucketsBlocked *bool `json:"new_buckets_blocked,omitempty"`
}

// GetPublicAccessBlock returns a tenant's block, or with tenant "" the
// cluster's (system admin) — for a tenant admin, "" is its own tenant's.
// Never-set reads as all flags clear.
func (c *Client) GetPublicAccessBlock(ctx context.Context, tenant string) (*AccountPublicAccessBlock, error) {
	var out AccountPublicAccessBlock
	if err := c.do(ctx, "GET", "/_admin/public-access-block", tenantQuery(tenant), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutPublicAccessBlock sets a tenant's block or, with tenant "" as the
// system admin, the cluster's. newBucketsBlocked is the cluster's default
// for new buckets; it is refused for a tenant, and nil keeps the cluster's
// current setting (true until set).
//
// The four flags are always written — this replaces the block, it does not
// merge into it.
func (c *Client) PutPublicAccessBlock(ctx context.Context, tenant string, block PublicAccessBlock, newBucketsBlocked *bool) (*AccountPublicAccessBlock, error) {
	// Tenant is not sent: the query names it, and the handler reads the
	// body's flags only.
	in := struct {
		PublicAccessBlock
		NewBucketsBlocked *bool `json:"new_buckets_blocked,omitempty"`
	}{block, newBucketsBlocked}
	var out AccountPublicAccessBlock
	if err := c.do(ctx, "PUT", "/_admin/public-access-block", tenantQuery(tenant), in, &out); err != nil {
		return nil, err
	}
	// The PUT answers with what it stored, which does not name the tenant.
	out.Tenant = tenant
	return &out, nil
}

// DeletePublicAccessBlock clears a tenant's (or the cluster's) block. For the
// cluster that also drops new_buckets_blocked, so new buckets go back to
// starting blocked.
func (c *Client) DeletePublicAccessBlock(ctx context.Context, tenant string) error {
	return c.do(ctx, "DELETE", "/_admin/public-access-block", tenantQuery(tenant), nil, nil)
}

// ---------------------------------------------------------------------------
// Bucket level. These are S3 API calls (`/{bucket}?publicAccessBlock`), not
// management ones, signed the same way; errors carry S3's Code.
// ---------------------------------------------------------------------------

type publicAccessBlockXML struct {
	XMLName xml.Name `xml:"PublicAccessBlockConfiguration"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`
	PublicAccessBlock
}

// GetBucketPublicAccessBlock returns the bucket's own block — not the
// effective one, which also includes its tenant's and the cluster's. A
// bucket with none is a 404 with Code NoSuchPublicAccessBlockConfiguration
// (IsNotFound).
func (c *Client) GetBucketPublicAccessBlock(ctx context.Context, bucket string) (*PublicAccessBlock, error) {
	raw, err := c.send(ctx, "GET", "/"+bucket, url.Values{"publicAccessBlock": {""}}, nil, "", true)
	if err != nil {
		return nil, err
	}
	var doc publicAccessBlockXML
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("objectio: decoding PublicAccessBlockConfiguration: %w", err)
	}
	return &doc.PublicAccessBlock, nil
}

// PutBucketPublicAccessBlock sets the bucket's own block.
func (c *Client) PutBucketPublicAccessBlock(ctx context.Context, bucket string, block PublicAccessBlock) error {
	body, err := xml.Marshal(publicAccessBlockXML{
		Xmlns:             "http://s3.amazonaws.com/doc/2006-03-01/",
		PublicAccessBlock: block,
	})
	if err != nil {
		return fmt.Errorf("objectio: encoding PublicAccessBlockConfiguration: %w", err)
	}
	_, err = c.send(ctx, "PUT", "/"+bucket, url.Values{"publicAccessBlock": {""}}, body, "application/xml", true)
	return err
}

// DeleteBucketPublicAccessBlock removes the bucket's own block. Its tenant's
// and the cluster's still hold.
func (c *Client) DeleteBucketPublicAccessBlock(ctx context.Context, bucket string) error {
	_, err := c.send(ctx, "DELETE", "/"+bucket, url.Values{"publicAccessBlock": {""}}, nil, "", true)
	return err
}

// GetBucketPolicyStatus reports whether the bucket's policy makes it public.
// A bucket with no policy is a 404 with Code NoSuchBucketPolicy.
func (c *Client) GetBucketPolicyStatus(ctx context.Context, bucket string) (bool, error) {
	raw, err := c.send(ctx, "GET", "/"+bucket, url.Values{"policyStatus": {""}}, nil, "", true)
	if err != nil {
		return false, err
	}
	var doc struct {
		IsPublic bool `xml:"IsPublic"`
	}
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return false, fmt.Errorf("objectio: decoding PolicyStatus: %w", err)
	}
	return doc.IsPublic, nil
}
