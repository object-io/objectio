package objectio

import "context"

// ---------------------------------------------------------------------------
// Audit stream
// ---------------------------------------------------------------------------

// AuditTarget is where audit events are sent: Type "webhook" (POSTs of
// JSON lines, retried until taken) or, for the cluster only, "stdout".
// A tenant's targets must be https URLs on a host the operator lists in
// the cluster's AllowedTenantHosts.
type AuditTarget struct {
	Type string `json:"type"`
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
	// AuthToken is sent as a bearer token. It reads back as "********";
	// writing that back keeps the stored token.
	AuthToken string `json:"auth_token,omitempty"`
	BatchSize int    `json:"batch_size,omitempty"`
	FlushMs   int    `json:"flush_ms,omitempty"`
	QueueSize int    `json:"queue_size,omitempty"`
}

// AuditConfig is the cluster's audit configuration (system admin) or a
// tenant's. A tenant receives the events on its buckets and by its users.
type AuditConfig struct {
	// Enabled and IncludeReads default to true when nil.
	Enabled      *bool         `json:"enabled,omitempty"`
	IncludeReads *bool         `json:"include_reads,omitempty"`
	Targets      []AuditTarget `json:"targets"`
	// AllowedTenantHosts is cluster-only: the hosts (host, host:port or
	// *.domain) tenants may send their events to.
	AllowedTenantHosts []string `json:"allowed_tenant_hosts,omitempty"`
	// Tenant is set on reads: whose configuration this is ("" = cluster).
	Tenant string `json:"tenant,omitempty"`
}

// GetAuditConfig returns the cluster's audit configuration (tenant "" as
// the system admin) or a tenant's. Never set is a 404 (IsNotFound).
func (c *Client) GetAuditConfig(ctx context.Context, tenant string) (*AuditConfig, error) {
	var out AuditConfig
	if err := c.do(ctx, "GET", "/_admin/audit", tenantQuery(tenant), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutAuditConfig replaces the cluster's or a tenant's audit configuration.
// Gateways pick it up within ten seconds; the one that took the call, at
// once.
func (c *Client) PutAuditConfig(ctx context.Context, tenant string, cfg AuditConfig) (*AuditConfig, error) {
	cfg.Tenant = ""
	if cfg.Targets == nil {
		cfg.Targets = []AuditTarget{}
	}
	var out AuditConfig
	if err := c.do(ctx, "PUT", "/_admin/audit", tenantQuery(tenant), cfg, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteAuditConfig removes the cluster's or a tenant's audit configuration.
func (c *Client) DeleteAuditConfig(ctx context.Context, tenant string) error {
	return c.do(ctx, "DELETE", "/_admin/audit", tenantQuery(tenant), nil, nil)
}
