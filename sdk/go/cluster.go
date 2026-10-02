package objectio

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
)

// Cluster operations, pools, KMS, Iceberg warehouses and metrics.
//
// The cluster and metrics reports are returned as raw JSON on purpose: they
// are large, operational, and grow fields release to release, so they are
// for dashboards and scripts to read rather than objects to edit. Pools,
// KMS keys and warehouses, which a caller does create and change, are
// typed.

// getRaw is a GET whose JSON answer is handed back unparsed.
func (c *Client) getRaw(ctx context.Context, path string, q url.Values) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.do(ctx, "GET", path, q, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Cluster (system admin)
// ---------------------------------------------------------------------------

// ClusterInfo returns the gateway's own topology and, for every active OSD,
// its distance from the gateway (GET /_admin/cluster-info). Raw JSON.
func (c *Client) ClusterInfo(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/_admin/cluster-info", nil)
}

// ListNodes returns every OSD, including ones marked out, with its state and
// disks (GET /_admin/nodes). Raw JSON.
func (c *Client) ListNodes(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/_admin/nodes", nil)
}

// Topology returns the OSD tree, region → zone → datacenter → rack → host (GET
// /_admin/topology). Raw JSON.
func (c *Client) Topology(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/_admin/topology", nil)
}

// Usage returns capacity and consumption per cluster, tenant and bucket (GET
// /_admin/usage). A tenant admin gets its own tenant's rows only and a null
// cluster section. It is gathered in the background, so a fresh gateway
// answers 503 until the first pass completes. Raw JSON.
func (c *Client) Usage(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/_admin/usage", nil)
}

// DrainStatus returns progress for each draining OSD, as {"drains": [...]}
// (GET /_admin/drain-status). Raw JSON.
func (c *Client) DrainStatus(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/_admin/drain-status", nil)
}

// RebalanceStatus returns the rebalancer's progress (GET
// /_admin/rebalance-status). Raw JSON.
func (c *Client) RebalanceStatus(ctx context.Context) (json.RawMessage, error) {
	return c.getRaw(ctx, "/_admin/rebalance-status", nil)
}

// PauseRebalance stops the cluster rebalancer. The pause is stored, so it
// survives restarts and meta leader changes until ResumeRebalance.
func (c *Client) PauseRebalance(ctx context.Context) error {
	return c.do(ctx, "POST", "/_admin/rebalance/pause", nil, nil, nil)
}

// ResumeRebalance re-enables the rebalancer.
func (c *Client) ResumeRebalance(ctx context.Context) error {
	return c.do(ctx, "POST", "/_admin/rebalance/resume", nil, nil, nil)
}

// OSD admin states for SetOSDAdminState.
const (
	OSDIn       = "in"
	OSDOut      = "out"
	OSDDraining = "draining"
)

// OSDStateChange is SetOSDAdminState's answer.
type OSDStateChange struct {
	// Found is false when no OSD has that ID.
	Found bool `json:"found"`
	// Changed is false when the OSD was already in that state.
	Changed bool   `json:"changed"`
	State   string `json:"state"`
}

// SetOSDAdminState marks an OSD in, out or draining. nodeID is the OSD's
// 32-hex-character ID as ListNodes reports it. Draining moves its shards
// elsewhere; follow it with DrainStatus.
func (c *Client) SetOSDAdminState(ctx context.Context, nodeID, state string) (*OSDStateChange, error) {
	var out OSDStateChange
	if err := c.do(ctx, "PUT", "/_admin/osds/"+nodeID+"/admin-state",
		nil, map[string]string{"state": state}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------------------------------------------------------------------------
// Pools (system admin)
// ---------------------------------------------------------------------------

// Pool is a storage pool: a data-protection scheme over a set of OSDs.
type Pool struct {
	Name string `json:"name"`
	// ECType is 0 for Reed-Solomon (MDS), 1 for LRC, 2 for replication.
	ECType int    `json:"ec_type"`
	ECK    uint32 `json:"ec_k"`
	ECM    uint32 `json:"ec_m"`
	// ECLocalParity and ECGlobalParity are for locally repairable codes.
	ECLocalParity  uint32 `json:"ec_local_parity"`
	ECGlobalParity uint32 `json:"ec_global_parity"`
	// ReplicationCount is the number of copies when ECType is replication.
	ReplicationCount uint32 `json:"replication_count"`
	// OSDTags restricts the pool to OSDs carrying these tags.
	OSDTags []string `json:"osd_tags"`
	// FailureDomain is the level shards are spread across: "rack" (the
	// server's default), "node", "datacenter".
	FailureDomain string `json:"failure_domain"`
	QuotaBytes    uint64 `json:"quota_bytes"`
	Description   string `json:"description"`
	Enabled       bool   `json:"enabled"`
	// PGCount, when non-zero, places by placement group rather than per
	// object. It is fixed at creation; grow by adding pools.
	PGCount   uint32 `json:"pg_count"`
	Tier      string `json:"tier"`
	CreatedAt int64  `json:"created_at,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

// ListPools returns every pool.
func (c *Client) ListPools(ctx context.Context) ([]Pool, error) {
	var out []Pool
	if err := c.do(ctx, "GET", "/_admin/pools", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreatePool creates a pool. Every field is sent as given, so set what the
// pool should have: in particular ECK/ECM (or ReplicationCount),
// FailureDomain and Enabled.
func (c *Client) CreatePool(ctx context.Context, p Pool) (*Pool, error) {
	var out Pool
	if err := c.do(ctx, "POST", "/_admin/pools", nil, p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPool returns one pool.
func (c *Client) GetPool(ctx context.Context, name string) (*Pool, error) {
	var out Pool
	if err := c.do(ctx, "GET", "/_admin/pools/"+name, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdatePool changes a pool by reading it, applying update, and writing it
// back. The server applies the fields sent to what it stores. The name
// cannot change.
func (c *Client) UpdatePool(ctx context.Context, name string, update func(*Pool)) (*Pool, error) {
	p, err := c.GetPool(ctx, name)
	if err != nil {
		return nil, err
	}
	update(p)
	p.Name = name
	var out Pool
	if err := c.do(ctx, "PUT", "/_admin/pools/"+name, nil, p, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeletePool removes a pool.
func (c *Client) DeletePool(ctx context.Context, name string) error {
	return c.do(ctx, "DELETE", "/_admin/pools/"+name, nil, nil, nil)
}

// ListPlacementGroups returns one page of a pool's placement groups with
// their OSDs, as {"pgs": [...], "next_pg_id": N}. Pass the previous page's
// next_pg_id as startAfter (0 for the first page); max 0 means the server's
// default of 1000. Raw JSON.
func (c *Client) ListPlacementGroups(ctx context.Context, pool string, startAfter, max uint32) (json.RawMessage, error) {
	q := url.Values{}
	if startAfter != 0 {
		q.Set("start_after", strconv.FormatUint(uint64(startAfter), 10))
	}
	if max != 0 {
		q.Set("max", strconv.FormatUint(uint64(max), 10))
	}
	return c.getRaw(ctx, "/_admin/pools/"+pool+"/placement-groups", q)
}

// ---------------------------------------------------------------------------
// KMS. Allowed by IAM policy (kms:* actions) as well as to admins; the key
// endpoints work only with the built-in local KMS.
// ---------------------------------------------------------------------------

// KMSStatus is whether server-side encryption with KMS keys is available.
type KMSStatus struct {
	Enabled bool `json:"enabled"`
	// Backend is "local", "external" (Vault or AWS KMS, whose keys are
	// managed there) or "disabled".
	Backend             string `json:"backend"`
	MasterKeyConfigured bool   `json:"master_key_configured"`
}

// KMSKey is a key-encryption key. Its material never leaves the gateway.
type KMSKey struct {
	KeyID       string `json:"key_id"`
	ARN         string `json:"arn"`
	Description string `json:"description"`
	// Status is "Enabled", "Disabled" or "PendingDeletion".
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
	CreatedBy string `json:"created_by"`
}

// KMSStatus reports the KMS backend.
func (c *Client) KMSStatus(ctx context.Context) (*KMSStatus, error) {
	var out KMSStatus
	if err := c.do(ctx, "GET", "/_admin/kms/status", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListKMSKeys returns the first page of keys (up to 100).
func (c *Client) ListKMSKeys(ctx context.Context) ([]KMSKey, error) {
	var out struct {
		Keys []KMSKey `json:"keys"`
	}
	if err := c.do(ctx, "GET", "/_admin/kms/keys", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// CreateKMSKey creates a key. keyID "" lets the server choose one.
func (c *Client) CreateKMSKey(ctx context.Context, keyID, description string) (*KMSKey, error) {
	var out KMSKey
	body := map[string]string{"key_id": keyID, "description": description}
	if err := c.do(ctx, "POST", "/_admin/kms/keys", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetKMSKey returns one key.
func (c *Client) GetKMSKey(ctx context.Context, keyID string) (*KMSKey, error) {
	var out KMSKey
	if err := c.do(ctx, "GET", "/_admin/kms/keys/"+keyID, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---------------------------------------------------------------------------
// Iceberg warehouses
// ---------------------------------------------------------------------------

// Warehouse is an Iceberg warehouse and the bucket backing it. Every Iceberg
// REST request names one with ?warehouse=.
type Warehouse struct {
	Name string `json:"name"`
	// Bucket is provisioned by the server, "iceberg-<name>".
	Bucket     string            `json:"bucket"`
	Location   string            `json:"location"`
	Tenant     string            `json:"tenant"`
	CreatedAt  int64             `json:"created_at,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// ListWarehouses returns the caller's tenant's warehouses (the system
// admin's: system scope's).
func (c *Client) ListWarehouses(ctx context.Context) ([]Warehouse, error) {
	var out struct {
		Warehouses []Warehouse `json:"warehouses"`
	}
	if err := c.do(ctx, "GET", "/_admin/warehouses", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Warehouses, nil
}

// CreateWarehouse creates a warehouse and its backing bucket. tenant ""
// uses the caller's own; properties may be nil.
func (c *Client) CreateWarehouse(ctx context.Context, name, tenant string, properties map[string]string) (*Warehouse, error) {
	body := map[string]any{"name": name}
	if tenant != "" {
		body["tenant"] = tenant
	}
	if len(properties) > 0 {
		body["properties"] = properties
	}
	var out Warehouse
	if err := c.do(ctx, "POST", "/_admin/warehouses", nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteWarehouse removes a warehouse.
func (c *Client) DeleteWarehouse(ctx context.Context, name string) error {
	return c.do(ctx, "DELETE", "/_admin/warehouses/"+name, nil, nil, nil)
}

// ---------------------------------------------------------------------------
// Metrics: a proxy to the Prometheus the gateway was pointed at
// (--prometheus-url). Without one, both answer 503.
// ---------------------------------------------------------------------------

// MetricsQuery runs an instant PromQL query and returns Prometheus's answer
// verbatim. at is RFC 3339 or a unix timestamp; "" means now.
func (c *Client) MetricsQuery(ctx context.Context, promql, at string) (json.RawMessage, error) {
	q := url.Values{"query": {promql}}
	if at != "" {
		q.Set("time", at)
	}
	return c.getRaw(ctx, "/_admin/metrics/query", q)
}

// MetricsQueryRange runs a range query. start and end are unix timestamps or
// RFC 3339, step is in seconds; more than 11,000 points is refused.
func (c *Client) MetricsQueryRange(ctx context.Context, promql, start, end, step string) (json.RawMessage, error) {
	q := url.Values{"query": {promql}, "start": {start}, "end": {end}, "step": {step}}
	return c.getRaw(ctx, "/_admin/metrics/query_range", q)
}
