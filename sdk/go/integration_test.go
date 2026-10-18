//go:build integration

package objectio

// Runs against a live gateway with the system admin's credential:
//
//	OBJECTIO_ENDPOINT=http://127.0.0.1:9000 OBJECTIO_ACCESS_KEY=… OBJECTIO_SECRET_KEY=… \
//	  go test -tags integration -run Integration -v ./...
//
// Everything it creates is named with a per-run suffix and removed at the
// end, so it can run against a cluster that has other things in it. It does
// touch the cluster-wide public access block, and restores it to unset.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func liveRoot(t *testing.T) (*Client, string) {
	t.Helper()
	endpoint := os.Getenv(EnvEndpoint)
	ak, sk := os.Getenv(EnvAccessKey), os.Getenv(EnvSecretKey)
	if endpoint == "" || ak == "" || sk == "" {
		t.Skipf("set %s, %s and %s (system admin) to run", EnvEndpoint, EnvAccessKey, EnvSecretKey)
	}
	c, err := New(Config{Endpoint: endpoint, AccessKey: ak, SecretKey: sk})
	if err != nil {
		t.Fatal(err)
	}
	return c, endpoint
}

// result lets a two-value call be checked inline: try(f()).must(t).
type result[T any] struct {
	v   T
	err error
}

func try[T any](v T, err error) result[T] { return result[T]{v, err} }

func (r result[T]) must(t *testing.T) T {
	t.Helper()
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.v
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func apiCode(err error) (int, string) {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.StatusCode, ae.Code
	}
	return 0, ""
}

// eventually retries f until it succeeds: gateways cache credentials for up
// to 15 seconds, so a key's status change is not seen at once.
func eventually(t *testing.T, what string, f func() error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: still failing after 30s: %v", what, err)
		}
		time.Sleep(time.Second)
	}
}

func TestIntegration(t *testing.T) {
	root, endpoint := liveRoot(t)
	ctx := context.Background()
	sfx := fmt.Sprintf("%x", time.Now().UnixNano()&0xffffffff)
	tenant := "sdkit" + sfx

	// ── tenant and tenant admin ──────────────────────────────────────────
	try(root.CreateTenant(ctx, Tenant{Name: tenant, DisplayName: "SDK IT", Enabled: true})).must(t)
	t.Cleanup(func() { _ = root.DeleteTenant(ctx, tenant) })

	prov := try(root.CreateUser(ctx, "prov-"+sfx, tenant)).must(t)
	t.Cleanup(func() { _ = root.DeleteUser(ctx, prov.UserID) })
	ok(t, root.AddTenantAdmin(ctx, tenant, prov.UserID))
	provKey := try(root.CreateAccessKey(ctx, prov.UserID, CreateAccessKeyInput{})).must(t)
	admin := try(New(Config{Endpoint: endpoint, AccessKey: provKey.AccessKeyID, SecretKey: provKey.SecretKey})).must(t)

	if u := try(admin.GetUser(ctx, prov.UserID)).must(t); u.Tenant != tenant || u.Status != UserActive {
		t.Fatalf("GetUser: %+v", u)
	}

	updated := try(root.UpdateTenant(ctx, tenant, func(tn *Tenant) {
		tn.DisplayName = "SDK IT renamed"
		tn.QuotaBuckets = 50
	})).must(t)
	if updated.DisplayName != "SDK IT renamed" || updated.QuotaBuckets != 50 ||
		!slices.Contains(updated.AdminUsers, prov.UserID) {
		t.Fatalf("UpdateTenant lost or failed a field: %+v", updated)
	}

	app := try(admin.CreateUser(ctx, "app-"+sfx, "")).must(t)
	t.Cleanup(func() { _ = root.DeleteUser(ctx, app.UserID) })
	if app.Tenant != tenant {
		t.Fatalf("tenant admin's user landed in %q", app.Tenant)
	}

	t.Run("policies", func(t *testing.T) {
		doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["s3:GetObject"],"Resource":["arn:obio:s3:::x/*"]}]}`)
		p := try(admin.CreatePolicy(ctx, "readers", doc, "", false)).must(t)
		defer func() { _ = admin.DeletePolicy(ctx, "readers", "") }()
		if p.Name != "readers" || p.Tenant != tenant {
			t.Fatalf("CreatePolicy: %+v", p)
		}
		// The system admin names the tenant; the tenant admin may not name
		// another.
		try(root.GetPolicy(ctx, "readers", tenant)).must(t)
		if _, err := admin.ListPolicies(ctx, "someone-else"); !IsForbidden(err) {
			t.Errorf("tenant admin listing another tenant: %v", err)
		}
		list := try(root.ListPolicies(ctx, tenant)).must(t)
		if !slices.ContainsFunc(list, func(p Policy) bool { return p.Name == "readers" }) {
			t.Errorf("ListPolicies: %+v", list)
		}
		doc2 := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["s3:GetObject","s3:ListBucket"],"Resource":["*"]}]}`)
		up := try(admin.UpdatePolicy(ctx, "readers", doc2, "")).must(t)
		if !strings.Contains(string(up.Policy), "s3:ListBucket") {
			t.Errorf("UpdatePolicy: %s", up.Policy)
		}
		if _, err := admin.CreatePolicy(ctx, "bad", json.RawMessage(`{"nope":1}`), "", false); err == nil {
			t.Error("a malformed policy document was accepted")
		}

		target := PolicyTarget{UserID: app.UserID}
		ok(t, admin.AttachPolicy(ctx, "readers", target, ""))
		if names := try(admin.ListAttachedPolicies(ctx, target, "")).must(t); !slices.Contains(names, "readers") {
			t.Errorf("attached: %v", names)
		}
		ok(t, admin.DetachPolicy(ctx, "readers", target, ""))
		if names := try(admin.ListAttachedPolicies(ctx, target, "")).must(t); slices.Contains(names, "readers") {
			t.Errorf("still attached: %v", names)
		}
	})

	t.Run("groups", func(t *testing.T) {
		g := try(admin.CreateGroup(ctx, "devs", "")).must(t)
		defer func() { _ = admin.DeleteGroup(ctx, g.GroupID) }()
		if g.Tenant != tenant || g.GroupID == "" {
			t.Fatalf("CreateGroup: %+v", g)
		}
		ok(t, admin.AddGroupMember(ctx, g.GroupID, app.UserID))
		if got := try(admin.GetGroup(ctx, g.GroupID)).must(t); !slices.Contains(got.MemberUserIDs, app.UserID) {
			t.Errorf("members: %v", got.MemberUserIDs)
		}
		groups := try(admin.ListGroups(ctx, "")).must(t)
		if !slices.ContainsFunc(groups, func(x Group) bool { return x.GroupID == g.GroupID }) {
			t.Errorf("ListGroups: %+v", groups)
		}
		ok(t, admin.RemoveGroupMember(ctx, g.GroupID, app.UserID))
		if got := try(admin.GetGroup(ctx, g.GroupID)).must(t); slices.Contains(got.MemberUserIDs, app.UserID) {
			t.Errorf("still a member: %v", got.MemberUserIDs)
		}
		ok(t, admin.DeleteGroup(ctx, g.GroupID))
		if _, err := admin.GetGroup(ctx, g.GroupID); !IsNotFound(err) {
			t.Errorf("deleted group: %v", err)
		}
	})

	t.Run("roles and sts", func(t *testing.T) {
		trust := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Principal":{"Federated":"https://idp.example.com"},
			"Action":"sts:AssumeRoleWithWebIdentity",
			"Condition":{"StringEquals":{"idp.example.com:sub":"ci"}}}]}`)
		r := try(admin.CreateRole(ctx, CreateRoleInput{
			Name: "ci", TrustPolicy: trust, Description: "CI jobs", MaxSessionSeconds: 7200})).must(t)
		defer func() { _ = admin.DeleteRole(ctx, "ci", "") }()
		if r.Tenant != tenant || r.MaxSessionSeconds != 7200 || !strings.HasSuffix(r.ARN, ":role/ci") {
			t.Fatalf("CreateRole: %+v", r)
		}
		desc := "CI and CD"
		if u := try(admin.UpdateRole(ctx, "ci", RoleUpdate{Description: &desc}, "")).must(t); u.Description != desc {
			t.Errorf("UpdateRole: %+v", u)
		}

		doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Action":["s3:*"],"Resource":["*"]}]}`)
		try(admin.CreatePolicy(ctx, "ci-access", doc, "", false)).must(t)
		defer func() { _ = admin.DeletePolicy(ctx, "ci-access", "") }()
		ok(t, admin.AttachPolicy(ctx, "ci-access", PolicyTarget{RoleName: "ci"}, ""))
		// The system admin reaches the same role by naming the tenant. GetRole
		// lists attached policies by stored key ("<tenant>/<name>") where
		// ListAttachedPolicies uses the plain name; accept either.
		got := try(root.GetRole(ctx, "ci", tenant)).must(t)
		if !slices.Contains(got.AttachedPolicies, "ci-access") && !slices.Contains(got.AttachedPolicies, tenant+"/ci-access") {
			t.Errorf("GetRole attached: %v", got.AttachedPolicies)
		}
		roles := try(admin.ListRoles(ctx, "")).must(t)
		if len(roles) != 1 || roles[0].Name != "ci" {
			t.Errorf("ListRoles: %+v", roles)
		}
		ok(t, admin.DetachPolicy(ctx, "ci-access", PolicyTarget{RoleName: "ci"}, ""))

		// STS on a client with no keys at all. With no identity provider for
		// the tenant there is nothing to vouch for the token, and the STS
		// error document comes back as an APIError carrying its code.
		sts := try(New(Config{Endpoint: endpoint})).must(t)
		_, err := sts.AssumeRoleWithWebIdentity(ctx, AssumeRoleWithWebIdentityInput{
			RoleArn: r.ARN, WebIdentityToken: "not.a.jwt", RoleSessionName: "it-run"})
		if status, code := apiCode(err); status != 400 || code != "InvalidIdentityToken" {
			t.Errorf("AssumeRoleWithWebIdentity: %v", err)
		}
		_, err = sts.AssumeRoleWithWebIdentity(ctx, AssumeRoleWithWebIdentityInput{
			RoleArn: r.ARN, WebIdentityToken: "x", RoleSessionName: "x"})
		if _, code := apiCode(err); code != "ValidationError" {
			t.Errorf("one-character session name: %v", err)
		}

		ok(t, admin.DeleteRole(ctx, "ci", ""))
		if _, err := admin.GetRole(ctx, "ci", ""); !IsNotFound(err) {
			t.Errorf("deleted role: %v", err)
		}
	})

	t.Run("suspend and deactivate", func(t *testing.T) {
		if u := try(admin.SuspendUser(ctx, app.UserID)).must(t); u.Status != UserSuspended {
			t.Errorf("SuspendUser: %+v", u)
		}
		if u := try(admin.GetUser(ctx, app.UserID)).must(t); u.Status != UserSuspended {
			t.Errorf("GetUser after suspend: %+v", u)
		}
		if u := try(admin.ActivateUser(ctx, app.UserID)).must(t); u.Status != UserActive {
			t.Errorf("ActivateUser: %+v", u)
		}
		if _, err := admin.SuspendUser(ctx, prov.UserID); err == nil {
			t.Error("a caller suspended itself")
		}

		// A second key for the tenant admin, deactivated before it is ever
		// used so no gateway has it cached as active.
		k2 := try(root.CreateAccessKey(ctx, prov.UserID, CreateAccessKeyInput{})).must(t)
		defer func() { _ = root.DeleteAccessKey(ctx, k2.AccessKeyID) }()
		if k := try(admin.DeactivateAccessKey(ctx, k2.AccessKeyID)).must(t); k.Status != KeyInactive {
			t.Errorf("DeactivateAccessKey: %+v", k)
		}
		c2 := try(New(Config{Endpoint: endpoint, AccessKey: k2.AccessKeyID, SecretKey: k2.SecretKey})).must(t)
		if _, err := c2.ListUsers(ctx); err == nil {
			t.Error("a request with a deactivated key succeeded")
		}
		if _, err := admin.DeactivateAccessKey(ctx, provKey.AccessKeyID); err == nil {
			t.Error("a caller deactivated the key it is signing with")
		}
		// The tenant's admin reactivates its tenant's key.
		if k := try(admin.ActivateAccessKey(ctx, k2.AccessKeyID)).must(t); k.Status != KeyActive {
			t.Errorf("ActivateAccessKey: %+v", k)
		}
		eventually(t, "request with the reactivated key", func() error {
			_, err := c2.ListUsers(ctx)
			return err
		})
	})

	t.Run("provisioning and public access", func(t *testing.T) {
		bucket := "sdkit-" + sfx
		ba := try(admin.ProvisionBucket(ctx, ProvisionBucketInput{Bucket: bucket, ProvisionerUserID: prov.UserID})).must(t)
		cleaned := false
		defer func() {
			if !cleaned {
				_ = admin.DeprovisionBucket(ctx, prov.UserID, bucket)
			}
		}()
		if ba.Scope != "s3://"+bucket+"/" || ba.SecretKey == "" {
			t.Fatalf("ProvisionBucket: %+v", ba)
		}

		// New buckets start with every flag set.
		if b := try(admin.GetBucketPublicAccessBlock(ctx, bucket)).must(t); *b != BlockAll {
			t.Errorf("new bucket's block: %+v", *b)
		}
		public := json.RawMessage(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
			"Principal":"*","Action":["s3:GetObject"],"Resource":["arn:obio:s3:::%s/*"]}]}`, bucket))
		// While blocked, a public policy is refused.
		if err := admin.PutBucketPolicy(ctx, bucket, public); !IsForbidden(err) {
			t.Errorf("public policy on a blocked bucket: %v", err)
		}

		ok(t, admin.PutBucketPublicAccessBlock(ctx, bucket, PublicAccessBlock{}))
		if b := try(admin.GetBucketPublicAccessBlock(ctx, bucket)).must(t); *b != (PublicAccessBlock{}) {
			t.Errorf("after clearing: %+v", *b)
		}
		if _, err := admin.GetBucketPolicyStatus(ctx, bucket); !IsNotFound(err) {
			t.Errorf("policy status with no policy: %v", err)
		} else if _, code := apiCode(err); code != "NoSuchBucketPolicy" {
			t.Errorf("code = %q", code)
		}
		ok(t, admin.PutBucketPolicy(ctx, bucket, public))
		if isPublic := try(admin.GetBucketPolicyStatus(ctx, bucket)).must(t); !isPublic {
			t.Error("a Principal * policy is not reported public")
		}
		ok(t, admin.DeleteBucketPolicy(ctx, bucket))

		ok(t, admin.DeleteBucketPublicAccessBlock(ctx, bucket))
		if _, err := admin.GetBucketPublicAccessBlock(ctx, bucket); !IsNotFound(err) {
			t.Errorf("after delete: %v", err)
		} else if _, code := apiCode(err); code != "NoSuchPublicAccessBlockConfiguration" {
			t.Errorf("code = %q", code)
		}

		// Tenant level, set by the tenant admin for its own tenant, read by
		// the system admin naming it.
		set := try(admin.PutPublicAccessBlock(ctx, "", PublicAccessBlock{BlockPublicPolicy: true}, nil)).must(t)
		if !set.BlockPublicPolicy || set.NewBucketsBlocked != nil {
			t.Errorf("PutPublicAccessBlock: %+v", set)
		}
		got := try(root.GetPublicAccessBlock(ctx, tenant)).must(t)
		if got.Tenant != tenant || !got.BlockPublicPolicy || got.RestrictPublicBuckets {
			t.Errorf("tenant block: %+v", got)
		}
		if _, err := admin.PutPublicAccessBlock(ctx, "", PublicAccessBlock{}, Bool(false)); err == nil {
			t.Error("a tenant set the cluster's new_buckets_blocked")
		}
		ok(t, admin.DeletePublicAccessBlock(ctx, ""))
		if got := try(root.GetPublicAccessBlock(ctx, tenant)).must(t); got.PublicAccessBlock != (PublicAccessBlock{}) {
			t.Errorf("tenant block after delete: %+v", got)
		}

		// Cluster level: system admin only, and restored to unset.
		cl := try(root.GetPublicAccessBlock(ctx, "")).must(t)
		if cl.Tenant != "" || cl.NewBucketsBlocked == nil {
			t.Errorf("cluster block: %+v", cl)
		}
		t.Cleanup(func() { _ = root.DeletePublicAccessBlock(ctx, "") })
		try(root.PutPublicAccessBlock(ctx, "", PublicAccessBlock{RestrictPublicBuckets: true}, Bool(true))).must(t)
		cl = try(root.GetPublicAccessBlock(ctx, "")).must(t)
		if !cl.RestrictPublicBuckets || cl.NewBucketsBlocked == nil || !*cl.NewBucketsBlocked {
			t.Errorf("cluster block after put: %+v", cl)
		}
		ok(t, root.DeletePublicAccessBlock(ctx, ""))

		// Rotation and teardown.
		rot := try(admin.RotateBucketKey(ctx, prov.UserID, bucket, true)).must(t)
		keys := try(admin.ListAccessKeys(ctx, prov.UserID)).must(t)
		ids := []string{}
		for _, k := range keys {
			ids = append(ids, k.AccessKeyID)
		}
		if !slices.Contains(ids, ba.AccessKeyID) || !slices.Contains(ids, rot.AccessKeyID) {
			t.Errorf("keys after rotation: %v", ids)
		}
		ok(t, admin.DeprovisionBucket(ctx, prov.UserID, bucket))
		cleaned = true
		keys = try(admin.ListAccessKeys(ctx, prov.UserID)).must(t)
		for _, k := range keys {
			if k.Scoped() {
				t.Errorf("scoped key survived deprovision: %+v", k)
			}
		}
		buckets := try(admin.ListBuckets(ctx)).must(t)
		if slices.ContainsFunc(buckets, func(b Bucket) bool { return b.Name == bucket }) {
			t.Error("bucket survived deprovision")
		}
	})

	t.Run("config and oidc", func(t *testing.T) {
		key := "sdk-it/" + sfx
		try(root.SetConfig(ctx, key, json.RawMessage(`{"a":1}`))).must(t)
		defer func() { _ = root.DeleteConfig(ctx, key) }()
		e := try(root.GetConfig(ctx, key)).must(t)
		if e.Key != key || string(e.Value) != `{"a":1}` {
			t.Errorf("GetConfig: %+v (%s)", e, e.Value)
		}
		list := try(root.ListConfig(ctx, "sdk-it/")).must(t)
		if !slices.ContainsFunc(list, func(e ConfigEntry) bool { return e.Key == key }) {
			t.Errorf("ListConfig: %+v", list)
		}
		ok(t, root.DeleteConfig(ctx, key))
		if _, err := root.GetConfig(ctx, key); !IsNotFound(err) {
			t.Errorf("deleted key: %v", err)
		}
		if _, err := admin.GetConfig(ctx, "rebalance/paused"); !IsForbidden(err) {
			t.Errorf("tenant admin reading cluster config: %v", err)
		}

		name := TenantOIDCProviderName(tenant)
		_, err := admin.PutOIDCProvider(ctx, name, OIDCProvider{
			IssuerURL: "https://idp.invalid", ClientID: "objectio", ClientSecret: "s3cret",
			Enabled: Bool(true), Extra: map[string]json.RawMessage{"vendor": json.RawMessage(`"keycloak"`)}})
		ok(t, err)
		defer func() { _ = root.DeleteOIDCProvider(ctx, name) }()
		p := try(admin.GetOIDCProvider(ctx, name)).must(t)
		if p.Name != name || p.IssuerURL != "https://idp.invalid" || p.ClientSecret != "********" ||
			string(p.Extra["vendor"]) != `"keycloak"` {
			t.Errorf("GetOIDCProvider: %+v", p)
		}
		// Writing its own provider binds the tenant to it.
		if tn := try(root.GetTenant(ctx, tenant)).must(t); tn.OIDCProvider != name {
			t.Errorf("tenant not bound to its provider: %q", tn.OIDCProvider)
		}
		providers := try(root.ListOIDCProviders(ctx)).must(t)
		if !slices.ContainsFunc(providers, func(p OIDCProvider) bool { return p.Name == name }) {
			t.Errorf("ListOIDCProviders: %+v", providers)
		}
		if _, err := admin.PutOIDCProvider(ctx, "not-mine", OIDCProvider{IssuerURL: "https://x", ClientID: "c"}); !IsForbidden(err) {
			t.Errorf("tenant admin writing another provider: %v", err)
		}
		ok(t, admin.DeleteOIDCProvider(ctx, name))
		if _, err := root.GetOIDCProvider(ctx, name); !IsNotFound(err) {
			t.Errorf("deleted provider: %v", err)
		}
	})

	t.Run("cluster", func(t *testing.T) {
		for name, f := range map[string]func(context.Context) (json.RawMessage, error){
			"ClusterInfo": root.ClusterInfo, "ListNodes": root.ListNodes, "Topology": root.Topology,
			"DrainStatus": root.DrainStatus, "RebalanceStatus": root.RebalanceStatus,
		} {
			raw, err := f(ctx)
			if err != nil {
				t.Errorf("%s: %v", name, err)
			} else if !json.Valid(raw) || len(raw) < 2 {
				t.Errorf("%s: %s", name, raw)
			}
		}
		// Usage is gathered in the background; a young gateway may not have it.
		if _, err := root.Usage(ctx); err != nil {
			if status, _ := apiCode(err); status != 503 {
				t.Errorf("Usage: %v", err)
			}
		}
		if _, err := admin.ListNodes(ctx); !IsForbidden(err) {
			t.Errorf("tenant admin listing nodes: %v", err)
		}

		pool := "sdkit-" + sfx
		created := try(root.CreatePool(ctx, Pool{Name: pool, ECK: 4, ECM: 2, FailureDomain: "node",
			Description: "sdk integration", Enabled: true})).must(t)
		defer func() { _ = root.DeletePool(ctx, pool) }()
		if created.ECK != 4 || created.ECM != 2 || created.FailureDomain != "node" {
			t.Errorf("CreatePool: %+v", created)
		}
		pools := try(root.ListPools(ctx)).must(t)
		if !slices.ContainsFunc(pools, func(p Pool) bool { return p.Name == pool }) {
			t.Errorf("ListPools: %+v", pools)
		}
		// UpdatePool changes one field and keeps the rest — the server alone
		// would reset EC to 3+2 and the failure domain to rack.
		up := try(root.UpdatePool(ctx, pool, func(p *Pool) { p.Description = "renamed" })).must(t)
		if up.Description != "renamed" || up.ECK != 4 || up.ECM != 2 || up.FailureDomain != "node" {
			t.Errorf("UpdatePool: %+v", up)
		}
		if p := try(root.GetPool(ctx, pool)).must(t); p.Description != "renamed" {
			t.Errorf("GetPool: %+v", p)
		}
		pgs := try(root.ListPlacementGroups(ctx, pool, 0, 10)).must(t)
		if !json.Valid(pgs) {
			t.Errorf("ListPlacementGroups: %s", pgs)
		}
		ok(t, root.DeletePool(ctx, pool))
		if _, err := root.GetPool(ctx, pool); !IsNotFound(err) {
			t.Errorf("deleted pool: %v", err)
		}

		st := try(root.KMSStatus(ctx)).must(t)
		if st.Backend == "" {
			t.Errorf("KMSStatus: %+v", st)
		}
	})
}
