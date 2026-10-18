package objectio

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// Named IAM policies, groups and roles.
//
// Each belongs to a tenant, or to system scope. A tenant admin manages its
// own tenant's and cannot name another; the system admin manages all and
// names the tenant it means. So every method here takes a tenant: "" means
// "the caller's own tenant" for a tenant admin, and "system scope" for the
// system admin.
//
// Names are unique per tenant, not globally: tenants "acme" and "globex"
// can each have a policy called "readers".

// tenantQuery is ?tenant= when one is named, and nothing otherwise.
//
// Sending tenant= with an empty value is not the same as leaving it out: the
// server reads it as naming the system scope, which a tenant admin is then
// refused.
func tenantQuery(tenant string) url.Values {
	if tenant == "" {
		return nil
	}
	return url.Values{"tenant": {tenant}}
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

// Policy is a named IAM policy document.
type Policy struct {
	Name string `json:"name"`
	// Tenant owns it; empty for a system policy.
	Tenant string `json:"tenant"`
	// Shared marks a system policy that tenants may attach (but not change).
	Shared bool `json:"shared"`
	// Policy is the document: {"Version", "Statement": [...]}.
	Policy    json.RawMessage `json:"policy"`
	CreatedAt int64           `json:"created_at,omitempty"`
	UpdatedAt int64           `json:"updated_at,omitempty"`
}

// ListPolicies returns the policies the caller can see in tenant. For the
// system admin, tenant "" lists every policy in every tenant; for a tenant
// admin it lists its own tenant's plus the shared system catalogue.
func (c *Client) ListPolicies(ctx context.Context, tenant string) ([]Policy, error) {
	var out struct {
		Policies []Policy `json:"policies"`
	}
	if err := c.do(ctx, "GET", "/_admin/policies", tenantQuery(tenant), nil, &out); err != nil {
		return nil, err
	}
	return out.Policies, nil
}

// CreatePolicy stores a named policy. The document is checked as the
// authorization chain will read it, so a malformed one is refused here
// rather than silently matching nothing later.
//
// shared publishes a system policy to tenants; only the system admin, in
// system scope (tenant ""), may set it.
func (c *Client) CreatePolicy(ctx context.Context, name string, document json.RawMessage, tenant string, shared bool) (*Policy, error) {
	body := map[string]any{"name": name, "policy": document}
	if shared {
		body["shared"] = true
	}
	var out Policy
	if err := c.do(ctx, "POST", "/_admin/policies", tenantQuery(tenant), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPolicy returns one policy. A tenant admin also sees a shared system
// policy by its name when its tenant has none of that name.
func (c *Client) GetPolicy(ctx context.Context, name, tenant string) (*Policy, error) {
	var out Policy
	if err := c.do(ctx, "GET", "/_admin/policies/"+name, tenantQuery(tenant), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdatePolicy replaces a policy's document in place, so it never stops
// applying to what it is attached to.
func (c *Client) UpdatePolicy(ctx context.Context, name string, document json.RawMessage, tenant string) (*Policy, error) {
	var out Policy
	body := map[string]any{"policy": document}
	if err := c.do(ctx, "PUT", "/_admin/policies/"+name, tenantQuery(tenant), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeletePolicy removes a policy.
func (c *Client) DeletePolicy(ctx context.Context, name, tenant string) error {
	return c.do(ctx, "DELETE", "/_admin/policies/"+name, tenantQuery(tenant), nil, nil)
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

// PolicyTarget names what a policy is attached to: exactly one of a user, a
// group or a role.
type PolicyTarget struct {
	UserID  string
	GroupID string
	// RoleName is a role's name within the tenant the call names (or the
	// caller's own).
	RoleName string
}

func (t PolicyTarget) fields() (map[string]string, error) {
	out := map[string]string{}
	if t.UserID != "" {
		out["user_id"] = t.UserID
	}
	if t.GroupID != "" {
		out["group_id"] = t.GroupID
	}
	if t.RoleName != "" {
		out["role_name"] = t.RoleName
	}
	if len(out) != 1 {
		// The server would silently pick the first of user, group, role; a
		// target naming two is almost certainly a bug in the caller.
		return nil, fmt.Errorf("objectio: PolicyTarget needs exactly one of UserID, GroupID or RoleName")
	}
	return out, nil
}

// AttachPolicy attaches a policy to a user, group or role. The policy is
// looked up in the target's tenant first, then among the system policies
// (a tenant admin may attach only shared ones).
//
// tenant matters only for a role, whose name is per tenant; users and groups
// carry their tenant already.
func (c *Client) AttachPolicy(ctx context.Context, policyName string, target PolicyTarget, tenant string) error {
	return c.changeAttachment(ctx, "/_admin/policies/attach", policyName, target, tenant)
}

// DetachPolicy reverses AttachPolicy.
func (c *Client) DetachPolicy(ctx context.Context, policyName string, target PolicyTarget, tenant string) error {
	return c.changeAttachment(ctx, "/_admin/policies/detach", policyName, target, tenant)
}

func (c *Client) changeAttachment(ctx context.Context, path, policyName string, target PolicyTarget, tenant string) error {
	body, err := target.fields()
	if err != nil {
		return err
	}
	body["policy_name"] = policyName
	if tenant != "" {
		// The attach endpoint reads the tenant from the body, not the query.
		body["tenant"] = tenant
	}
	return c.do(ctx, "POST", path, nil, body, nil)
}

// ListAttachedPolicies returns the names of the policies attached to a user,
// group or role. A tenant's policies are listed by plain name.
func (c *Client) ListAttachedPolicies(ctx context.Context, target PolicyTarget, tenant string) ([]string, error) {
	fields, err := target.fields()
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	for k, v := range fields {
		q.Set(k, v)
	}
	if tenant != "" {
		q.Set("tenant", tenant)
	}
	var out struct {
		PolicyNames []string `json:"policy_names"`
	}
	if err := c.do(ctx, "GET", "/_admin/policies/attached", q, nil, &out); err != nil {
		return nil, err
	}
	return out.PolicyNames, nil
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

// Group is a set of users of one tenant. A policy attached to the group
// applies to each member.
type Group struct {
	GroupID       string   `json:"group_id"`
	GroupName     string   `json:"group_name"`
	ARN           string   `json:"arn,omitempty"`
	Tenant        string   `json:"tenant"`
	MemberUserIDs []string `json:"member_user_ids"`
	CreatedAt     int64    `json:"created_at,omitempty"`
}

// ListGroups returns the groups in tenant (for the system admin, "" lists
// every group in every tenant).
func (c *Client) ListGroups(ctx context.Context, tenant string) ([]Group, error) {
	var out struct {
		Groups []Group `json:"groups"`
	}
	if err := c.do(ctx, "GET", "/_admin/groups", tenantQuery(tenant), nil, &out); err != nil {
		return nil, err
	}
	return out.Groups, nil
}

// CreateGroup creates a group in tenant. Groups are addressed by the
// GroupID the server assigns, not by name.
func (c *Client) CreateGroup(ctx context.Context, name, tenant string) (*Group, error) {
	var out Group
	body := map[string]string{"group_name": name}
	if err := c.do(ctx, "POST", "/_admin/groups", tenantQuery(tenant), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetGroup returns one group with its members.
func (c *Client) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	var out Group
	if err := c.do(ctx, "GET", "/_admin/groups/"+groupID, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteGroup removes a group. Its members' own policies are untouched.
func (c *Client) DeleteGroup(ctx context.Context, groupID string) error {
	return c.do(ctx, "DELETE", "/_admin/groups/"+groupID, nil, nil, nil)
}

// AddGroupMember adds a user to a group. The user must be in the group's
// tenant.
func (c *Client) AddGroupMember(ctx context.Context, groupID, userID string) error {
	return c.do(ctx, "POST", "/_admin/groups/"+groupID+"/members",
		nil, map[string]string{"user_id": userID}, nil)
}

// RemoveGroupMember removes a user from a group.
func (c *Client) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	return c.do(ctx, "DELETE", "/_admin/groups/"+groupID+"/members/"+userID, nil, nil, nil)
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

// Role is an identity that is assumed rather than logged into: a workload
// exchanges an OIDC token for the role's temporary credentials with
// AssumeRoleWithWebIdentity, and the role's trust policy decides whose
// tokens qualify.
type Role struct {
	Name string `json:"name"`
	// ARN is what AssumeRoleWithWebIdentity takes:
	// arn:obio:iam::<tenant>:role/<name>, or ::objectio: for system scope.
	ARN         string          `json:"arn"`
	Tenant      string          `json:"tenant"`
	Description string          `json:"description,omitempty"`
	TrustPolicy json.RawMessage `json:"trust_policy"`
	// MaxSessionSeconds caps how long assumed credentials last; 0 is the
	// server default (one hour).
	MaxSessionSeconds uint32 `json:"max_session_seconds"`
	CreatedAt         int64  `json:"created_at,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	// AttachedPolicies is filled in by GetRole only. The server lists them by
	// stored key — "<tenant>/<name>" for a tenant's policy, the plain name
	// for a system one — where ListAttachedPolicies gives plain names.
	AttachedPolicies []string `json:"attached_policies,omitempty"`
}

// CreateRoleInput describes a new role.
type CreateRoleInput struct {
	Name string
	// TrustPolicy says who may assume the role, e.g. a statement with
	// "Principal": {"Federated": "<issuer URL>"}, "Action":
	// "sts:AssumeRoleWithWebIdentity" and a condition on the token's claims
	// keyed "<issuer host>:sub" (or :aud, :groups, :email, any claim).
	TrustPolicy       json.RawMessage
	Description       string
	MaxSessionSeconds uint32
	// Tenant the role belongs to; "" as for every IAM call.
	Tenant string
}

// ListRoles returns the roles in tenant (for the system admin, "" lists
// every role in every tenant).
func (c *Client) ListRoles(ctx context.Context, tenant string) ([]Role, error) {
	var out struct {
		Roles []Role `json:"roles"`
	}
	if err := c.do(ctx, "GET", "/_admin/roles", tenantQuery(tenant), nil, &out); err != nil {
		return nil, err
	}
	return out.Roles, nil
}

// CreateRole creates a role. A role has no rights of its own until a policy
// is attached to it (AttachPolicy with PolicyTarget{RoleName: ...}).
func (c *Client) CreateRole(ctx context.Context, in CreateRoleInput) (*Role, error) {
	body := map[string]any{"name": in.Name, "trust_policy": in.TrustPolicy}
	if in.Description != "" {
		body["description"] = in.Description
	}
	if in.MaxSessionSeconds != 0 {
		body["max_session_seconds"] = in.MaxSessionSeconds
	}
	var out Role
	if err := c.do(ctx, "POST", "/_admin/roles", tenantQuery(in.Tenant), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRole returns a role with the names of the policies attached to it.
func (c *Client) GetRole(ctx context.Context, name, tenant string) (*Role, error) {
	var out Role
	if err := c.do(ctx, "GET", "/_admin/roles/"+name, tenantQuery(tenant), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RoleUpdate is a partial change to a role: nil fields are left as they are.
type RoleUpdate struct {
	TrustPolicy       json.RawMessage `json:"trust_policy,omitempty"`
	Description       *string         `json:"description,omitempty"`
	MaxSessionSeconds *uint32         `json:"max_session_seconds,omitempty"`
}

// UpdateRole changes a role's trust policy, description or session limit.
func (c *Client) UpdateRole(ctx context.Context, name string, in RoleUpdate, tenant string) (*Role, error) {
	var out Role
	if err := c.do(ctx, "PUT", "/_admin/roles/"+name, tenantQuery(tenant), in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRole removes a role.
func (c *Client) DeleteRole(ctx context.Context, name, tenant string) error {
	return c.do(ctx, "DELETE", "/_admin/roles/"+name, tenantQuery(tenant), nil, nil)
}
