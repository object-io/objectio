package objectio

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// These pin the request each method sends — verb, path, query, body — to
// what the gateway's handler reads. A wrong field name here is not a compile
// error and not a server error either: the handler reads a missing field as
// empty and quietly does something else.

type recorded struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
	Header http.Header
}

// recorder answers every request with status/contentType/body and keeps the
// last request.
type recorder struct {
	mu          sync.Mutex
	last        recorded
	status      int
	contentType string
	body        string
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.last = recorded{req.Method, req.URL.Path, req.URL.Query(), b, req.Header.Clone()}
	status, ct, body := r.status, r.contentType, r.body
	r.mu.Unlock()
	if ct == "" {
		ct = "application/json"
	}
	w.Header().Set("Content-Type", ct)
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func newTestClient(t *testing.T, rec *recorder, withKeys bool) *Client {
	t.Helper()
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	cfg := Config{Endpoint: srv.URL}
	if withKeys {
		cfg.AccessKey, cfg.SecretKey = testAccessKey, testSecretKey
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// jsonEqual compares a request body with the expected JSON, ignoring key
// order. want "" means no body.
func jsonEqual(t *testing.T, got []byte, want string) {
	t.Helper()
	if want == "" {
		if len(got) != 0 {
			t.Errorf("body = %s, want none", got)
		}
		return
	}
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("body %q is not JSON: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad want %q: %v", want, err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("body = %s, want %s", got, want)
	}
}

func TestRequestShapes(t *testing.T) {
	ctx := context.Background()
	doc := json.RawMessage(`{"Version":"2012-10-17","Statement":[]}`)
	cases := []struct {
		name   string
		reply  string
		call   func(c *Client) error
		method string
		path   string
		query  string // url.Values.Encode() form
		body   string // JSON; "" for none
	}{
		// users and keys
		{"GetUser", `{"user_id":"u1"}`, func(c *Client) error { _, err := c.GetUser(ctx, "u1"); return err },
			"GET", "/_admin/users/u1", "", ""},
		{"UpdateUser", `{}`, func(c *Client) error {
			e := "a@b.c"
			_, err := c.UpdateUser(ctx, "u1", UserUpdate{Email: &e})
			return err
		}, "PUT", "/_admin/users/u1", "", `{"email":"a@b.c"}`},
		{"SuspendUser", `{}`, func(c *Client) error { _, err := c.SuspendUser(ctx, "u1"); return err },
			"PUT", "/_admin/users/u1", "", `{"status":"suspended"}`},
		{"ActivateUser", `{}`, func(c *Client) error { _, err := c.ActivateUser(ctx, "u1"); return err },
			"PUT", "/_admin/users/u1", "", `{"status":"active"}`},
		{"DeactivateAccessKey", `{}`, func(c *Client) error { _, err := c.DeactivateAccessKey(ctx, "AK1"); return err },
			"PUT", "/_admin/access-keys/AK1", "", `{"status":"inactive"}`},
		{"ActivateAccessKey", `{}`, func(c *Client) error { _, err := c.ActivateAccessKey(ctx, "AK1"); return err },
			"PUT", "/_admin/access-keys/AK1", "", `{"status":"active"}`},

		// audit
		{"GetAuditConfig", `{"targets":[]}`, func(c *Client) error { _, err := c.GetAuditConfig(ctx, "acme"); return err },
			"GET", "/_admin/audit", "tenant=acme", ""},
		{"PutAuditConfig", `{"targets":[]}`, func(c *Client) error {
			_, err := c.PutAuditConfig(ctx, "", AuditConfig{
				Targets:            []AuditTarget{{Type: "webhook", Name: "siem", URL: "https://siem/x"}},
				AllowedTenantHosts: []string{"siem.acme.example"},
			})
			return err
		}, "PUT", "/_admin/audit", "", `{"targets":[{"type":"webhook","name":"siem","url":"https://siem/x"}],"allowed_tenant_hosts":["siem.acme.example"]}`},
		{"DeleteAuditConfig", ``, func(c *Client) error { return c.DeleteAuditConfig(ctx, "acme") },
			"DELETE", "/_admin/audit", "tenant=acme", ""},

		// policies
		{"ListPolicies system", `{"policies":[]}`, func(c *Client) error { _, err := c.ListPolicies(ctx, ""); return err },
			"GET", "/_admin/policies", "", ""},
		{"ListPolicies tenant", `{"policies":[]}`, func(c *Client) error { _, err := c.ListPolicies(ctx, "acme"); return err },
			"GET", "/_admin/policies", "tenant=acme", ""},
		{"CreatePolicy", `{}`, func(c *Client) error { _, err := c.CreatePolicy(ctx, "readers", doc, "acme", false); return err },
			"POST", "/_admin/policies", "tenant=acme", `{"name":"readers","policy":{"Version":"2012-10-17","Statement":[]}}`},
		{"CreatePolicy shared", `{}`, func(c *Client) error { _, err := c.CreatePolicy(ctx, "ro", doc, "", true); return err },
			"POST", "/_admin/policies", "", `{"name":"ro","policy":{"Version":"2012-10-17","Statement":[]},"shared":true}`},
		{"GetPolicy", `{}`, func(c *Client) error { _, err := c.GetPolicy(ctx, "readers", "acme"); return err },
			"GET", "/_admin/policies/readers", "tenant=acme", ""},
		{"UpdatePolicy", `{}`, func(c *Client) error { _, err := c.UpdatePolicy(ctx, "readers", doc, ""); return err },
			"PUT", "/_admin/policies/readers", "", `{"policy":{"Version":"2012-10-17","Statement":[]}}`},
		{"DeletePolicy", ``, func(c *Client) error { return c.DeletePolicy(ctx, "readers", "acme") },
			"DELETE", "/_admin/policies/readers", "tenant=acme", ""},
		{"AttachPolicy user", ``, func(c *Client) error { return c.AttachPolicy(ctx, "readers", PolicyTarget{UserID: "u1"}, "") },
			"POST", "/_admin/policies/attach", "", `{"policy_name":"readers","user_id":"u1"}`},
		{"AttachPolicy role", ``, func(c *Client) error {
			return c.AttachPolicy(ctx, "readers", PolicyTarget{RoleName: "ci"}, "acme")
		}, "POST", "/_admin/policies/attach", "", `{"policy_name":"readers","role_name":"ci","tenant":"acme"}`},
		{"DetachPolicy group", ``, func(c *Client) error { return c.DetachPolicy(ctx, "readers", PolicyTarget{GroupID: "g1"}, "") },
			"POST", "/_admin/policies/detach", "", `{"policy_name":"readers","group_id":"g1"}`},
		{"ListAttachedPolicies", `{"policy_names":["a"]}`, func(c *Client) error {
			_, err := c.ListAttachedPolicies(ctx, PolicyTarget{RoleName: "ci"}, "acme")
			return err
		}, "GET", "/_admin/policies/attached", "role_name=ci&tenant=acme", ""},

		// groups
		{"ListGroups", `{"groups":[]}`, func(c *Client) error { _, err := c.ListGroups(ctx, "acme"); return err },
			"GET", "/_admin/groups", "tenant=acme", ""},
		{"CreateGroup", `{}`, func(c *Client) error { _, err := c.CreateGroup(ctx, "devs", "acme"); return err },
			"POST", "/_admin/groups", "tenant=acme", `{"group_name":"devs"}`},
		{"GetGroup", `{}`, func(c *Client) error { _, err := c.GetGroup(ctx, "g1"); return err },
			"GET", "/_admin/groups/g1", "", ""},
		{"DeleteGroup", ``, func(c *Client) error { return c.DeleteGroup(ctx, "g1") },
			"DELETE", "/_admin/groups/g1", "", ""},
		{"AddGroupMember", ``, func(c *Client) error { return c.AddGroupMember(ctx, "g1", "u1") },
			"POST", "/_admin/groups/g1/members", "", `{"user_id":"u1"}`},
		{"RemoveGroupMember", ``, func(c *Client) error { return c.RemoveGroupMember(ctx, "g1", "u1") },
			"DELETE", "/_admin/groups/g1/members/u1", "", ""},

		// roles
		{"ListRoles", `{"roles":[]}`, func(c *Client) error { _, err := c.ListRoles(ctx, ""); return err },
			"GET", "/_admin/roles", "", ""},
		{"CreateRole", `{}`, func(c *Client) error {
			_, err := c.CreateRole(ctx, CreateRoleInput{Name: "ci", TrustPolicy: doc, Description: "d",
				MaxSessionSeconds: 7200, Tenant: "acme"})
			return err
		}, "POST", "/_admin/roles", "tenant=acme",
			`{"name":"ci","trust_policy":{"Version":"2012-10-17","Statement":[]},"description":"d","max_session_seconds":7200}`},
		{"GetRole", `{}`, func(c *Client) error { _, err := c.GetRole(ctx, "ci", "acme"); return err },
			"GET", "/_admin/roles/ci", "tenant=acme", ""},
		{"UpdateRole", `{}`, func(c *Client) error {
			d := "new"
			_, err := c.UpdateRole(ctx, "ci", RoleUpdate{Description: &d}, "")
			return err
		}, "PUT", "/_admin/roles/ci", "", `{"description":"new"}`},
		{"DeleteRole", ``, func(c *Client) error { return c.DeleteRole(ctx, "ci", "acme") },
			"DELETE", "/_admin/roles/ci", "tenant=acme", ""},

		// config and OIDC
		{"ListConfig", `[]`, func(c *Client) error { _, err := c.ListConfig(ctx, "identity/"); return err },
			"GET", "/_admin/config", "prefix=identity%2F", ""},
		{"GetConfig", `{"key":"a/b","value":1}`, func(c *Client) error { _, err := c.GetConfig(ctx, "a/b"); return err },
			"GET", "/_admin/config/a/b", "", ""},
		{"SetConfig", `{"key":"a/b","value":{"x":1}}`, func(c *Client) error {
			_, err := c.SetConfig(ctx, "a/b", json.RawMessage(`{"x":1}`))
			return err
		}, "PUT", "/_admin/config/a/b", "", `{"x":1}`},
		{"DeleteConfig", ``, func(c *Client) error { return c.DeleteConfig(ctx, "a/b") },
			"DELETE", "/_admin/config/a/b", "", ""},
		{"ListOIDCProviders", `[]`, func(c *Client) error { _, err := c.ListOIDCProviders(ctx); return err },
			"GET", "/_admin/config", "prefix=identity%2Fopenid%2F", ""},
		{"PutOIDCProvider", `{"key":"identity/openid/t-acme","value":{}}`, func(c *Client) error {
			_, err := c.PutOIDCProvider(ctx, TenantOIDCProviderName("ACME"), OIDCProvider{
				IssuerURL: "https://idp", ClientID: "cid", Enabled: Bool(true)})
			return err
		}, "PUT", "/_admin/config/identity/openid/t-acme", "", `{"issuer_url":"https://idp","client_id":"cid","enabled":true}`},
		{"DeleteOIDCProvider", ``, func(c *Client) error { return c.DeleteOIDCProvider(ctx, "kc") },
			"DELETE", "/_admin/config/identity/openid/kc", "", ""},

		// public access block
		{"GetPublicAccessBlock cluster", `{}`, func(c *Client) error { _, err := c.GetPublicAccessBlock(ctx, ""); return err },
			"GET", "/_admin/public-access-block", "", ""},
		{"PutPublicAccessBlock tenant", `{}`, func(c *Client) error {
			_, err := c.PutPublicAccessBlock(ctx, "acme", PublicAccessBlock{BlockPublicPolicy: true}, nil)
			return err
		}, "PUT", "/_admin/public-access-block", "tenant=acme",
			`{"BlockPublicAcls":false,"IgnorePublicAcls":false,"BlockPublicPolicy":true,"RestrictPublicBuckets":false}`},
		{"PutPublicAccessBlock cluster default", `{}`, func(c *Client) error {
			_, err := c.PutPublicAccessBlock(ctx, "", PublicAccessBlock{}, Bool(false))
			return err
		}, "PUT", "/_admin/public-access-block", "",
			`{"BlockPublicAcls":false,"IgnorePublicAcls":false,"BlockPublicPolicy":false,"RestrictPublicBuckets":false,"new_buckets_blocked":false}`},
		{"DeletePublicAccessBlock", ``, func(c *Client) error { return c.DeletePublicAccessBlock(ctx, "acme") },
			"DELETE", "/_admin/public-access-block", "tenant=acme", ""},
		{"DeleteBucketPublicAccessBlock", ``, func(c *Client) error { return c.DeleteBucketPublicAccessBlock(ctx, "b1") },
			"DELETE", "/b1", "publicAccessBlock=", ""},

		// buckets
		{"GetBucketDedup", `{}`, func(c *Client) error { _, err := c.GetBucketDedup(ctx, "b1"); return err },
			"GET", "/_admin/buckets/b1/dedup", "", ""},
		{"SetBucketDedup", `{}`, func(c *Client) error {
			_, err := c.SetBucketDedup(ctx, "b1", DedupPolicy{Mode: "on"})
			return err
		}, "PUT", "/_admin/buckets/b1/dedup", "", `{"mode":"on"}`},

		// cluster
		{"ClusterInfo", `{}`, func(c *Client) error { _, err := c.ClusterInfo(ctx); return err },
			"GET", "/_admin/cluster-info", "", ""},
		{"ListNodes", `[]`, func(c *Client) error { _, err := c.ListNodes(ctx); return err },
			"GET", "/_admin/nodes", "", ""},
		{"Topology", `{}`, func(c *Client) error { _, err := c.Topology(ctx); return err },
			"GET", "/_admin/topology", "", ""},
		{"Usage", `{}`, func(c *Client) error { _, err := c.Usage(ctx); return err },
			"GET", "/_admin/usage", "", ""},
		{"DrainStatus", `{}`, func(c *Client) error { _, err := c.DrainStatus(ctx); return err },
			"GET", "/_admin/drain-status", "", ""},
		{"RebalanceStatus", `{}`, func(c *Client) error { _, err := c.RebalanceStatus(ctx); return err },
			"GET", "/_admin/rebalance-status", "", ""},
		{"PauseRebalance", `{"paused":true}`, func(c *Client) error { return c.PauseRebalance(ctx) },
			"POST", "/_admin/rebalance/pause", "", ""},
		{"ResumeRebalance", `{"paused":false}`, func(c *Client) error { return c.ResumeRebalance(ctx) },
			"POST", "/_admin/rebalance/resume", "", ""},
		{"SetOSDAdminState", `{}`, func(c *Client) error {
			_, err := c.SetOSDAdminState(ctx, "00112233445566778899aabbccddeeff", OSDOut)
			return err
		}, "PUT", "/_admin/osds/00112233445566778899aabbccddeeff/admin-state", "", `{"state":"out"}`},
		{"ListPools", `[]`, func(c *Client) error { _, err := c.ListPools(ctx); return err },
			"GET", "/_admin/pools", "", ""},
		{"GetPool", `{}`, func(c *Client) error { _, err := c.GetPool(ctx, "p1"); return err },
			"GET", "/_admin/pools/p1", "", ""},
		{"DeletePool", ``, func(c *Client) error { return c.DeletePool(ctx, "p1") },
			"DELETE", "/_admin/pools/p1", "", ""},
		{"ListPlacementGroups", `{}`, func(c *Client) error { _, err := c.ListPlacementGroups(ctx, "p1", 7, 50); return err },
			"GET", "/_admin/pools/p1/placement-groups", "max=50&start_after=7", ""},
		{"KMSStatus", `{}`, func(c *Client) error { _, err := c.KMSStatus(ctx); return err },
			"GET", "/_admin/kms/status", "", ""},
		{"ListKMSKeys", `{"keys":[]}`, func(c *Client) error { _, err := c.ListKMSKeys(ctx); return err },
			"GET", "/_admin/kms/keys", "", ""},
		{"CreateKMSKey", `{}`, func(c *Client) error { _, err := c.CreateKMSKey(ctx, "k1", "d"); return err },
			"POST", "/_admin/kms/keys", "", `{"key_id":"k1","description":"d"}`},
		{"GetKMSKey", `{}`, func(c *Client) error { _, err := c.GetKMSKey(ctx, "k1"); return err },
			"GET", "/_admin/kms/keys/k1", "", ""},
		{"ListWarehouses", `{"warehouses":[]}`, func(c *Client) error { _, err := c.ListWarehouses(ctx); return err },
			"GET", "/_admin/warehouses", "", ""},
		{"CreateWarehouse", `{}`, func(c *Client) error { _, err := c.CreateWarehouse(ctx, "wh", "acme", nil); return err },
			"POST", "/_admin/warehouses", "", `{"name":"wh","tenant":"acme"}`},
		{"DeleteWarehouse", ``, func(c *Client) error { return c.DeleteWarehouse(ctx, "wh") },
			"DELETE", "/_admin/warehouses/wh", "", ""},
		{"MetricsQuery", `{}`, func(c *Client) error { _, err := c.MetricsQuery(ctx, "up", ""); return err },
			"GET", "/_admin/metrics/query", "query=up", ""},
		{"MetricsQueryRange", `{}`, func(c *Client) error {
			_, err := c.MetricsQueryRange(ctx, "rate(x[5m])", "1", "61", "15")
			return err
		}, "GET", "/_admin/metrics/query_range", "end=61&query=rate%28x%5B5m%5D%29&start=1&step=15", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{body: tc.reply}
			c := newTestClient(t, rec, true)
			if err := tc.call(c); err != nil {
				t.Fatal(err)
			}
			got := rec.last
			if got.Method != tc.method || got.Path != tc.path {
				t.Errorf("sent %s %s, want %s %s", got.Method, got.Path, tc.method, tc.path)
			}
			if q := got.Query.Encode(); q != tc.query {
				t.Errorf("query = %q, want %q", q, tc.query)
			}
			jsonEqual(t, got.Body, tc.body)
			if !strings.HasPrefix(got.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
				t.Errorf("request is not signed")
			}
		})
	}
}

func TestUpdateTenantIsReadModifyWrite(t *testing.T) {
	// The server replaces a tenant wholesale, so what is not sent is reset.
	// UpdateTenant must therefore send back everything it read.
	var mu sync.Mutex
	var puts [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_admin/tenants/acme" {
			t.Errorf("path %s", r.URL.Path)
		}
		switch r.Method {
		case "GET":
			_, _ = io.WriteString(w, `{"name":"acme","display_name":"Acme","admin_users":["u1"],
				"quota_bytes":100,"labels":{"k":"v"},"enabled":true,"dedup":{"mode":"on","scope":"tenant"}}`)
		case "PUT":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			puts = append(puts, b)
			mu.Unlock()
			_, _ = w.Write(b)
		default:
			t.Errorf("method %s", r.Method)
		}
	}))
	defer srv.Close()
	c, _ := New(Config{Endpoint: srv.URL, AccessKey: "a", SecretKey: "b"})
	out, err := c.UpdateTenant(context.Background(), "acme", func(t *Tenant) { t.QuotaBytes = 200 })
	if err != nil {
		t.Fatal(err)
	}
	if out.QuotaBytes != 200 || len(puts) != 1 {
		t.Fatalf("out=%+v puts=%d", out, len(puts))
	}
	jsonEqual(t, puts[0], `{"name":"acme","display_name":"Acme","admin_users":["u1"],
		"quota_bytes":200,"labels":{"k":"v"},"enabled":true,"dedup":{"mode":"on","scope":"tenant"}}`)
}

func TestPolicyTargetNeedsExactlyOne(t *testing.T) {
	rec := &recorder{}
	c := newTestClient(t, rec, true)
	for _, target := range []PolicyTarget{{}, {UserID: "u", GroupID: "g"}} {
		if err := c.AttachPolicy(context.Background(), "p", target, ""); err == nil {
			t.Errorf("%+v: expected an error", target)
		}
	}
	if rec.last.Method != "" {
		t.Error("an invalid target still sent a request")
	}
}

func TestBucketPublicAccessBlockIsXML(t *testing.T) {
	rec := &recorder{}
	c := newTestClient(t, rec, true)
	ctx := context.Background()

	if err := c.PutBucketPublicAccessBlock(ctx, "b1", PublicAccessBlock{BlockPublicPolicy: true}); err != nil {
		t.Fatal(err)
	}
	if rec.last.Method != "PUT" || rec.last.Path != "/b1" || rec.last.Query.Encode() != "publicAccessBlock=" {
		t.Errorf("sent %s %s?%s", rec.last.Method, rec.last.Path, rec.last.Query.Encode())
	}
	var sent struct {
		XMLName xml.Name
		PublicAccessBlock
	}
	if err := xml.Unmarshal(rec.last.Body, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.XMLName.Local != "PublicAccessBlockConfiguration" ||
		sent.PublicAccessBlock != (PublicAccessBlock{BlockPublicPolicy: true}) {
		t.Errorf("sent %s", rec.last.Body)
	}
	// Each of the four flags must be present: the server reads an absent
	// one as false, which is right here, but a typo in a tag would be too.
	for _, f := range []string{"BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"} {
		if !strings.Contains(string(rec.last.Body), "<"+f+">") {
			t.Errorf("body lacks %s: %s", f, rec.last.Body)
		}
	}

	// What the gateway answers with, verbatim.
	rec.contentType = "application/xml"
	rec.body = `<?xml version="1.0" encoding="UTF-8"?>
<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>`
	got, err := c.GetBucketPublicAccessBlock(ctx, "b1")
	if err != nil {
		t.Fatal(err)
	}
	want := PublicAccessBlock{BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true}
	if *got != want {
		t.Errorf("got %+v", *got)
	}
	if rec.last.Query.Encode() != "publicAccessBlock=" {
		t.Errorf("query %q", rec.last.Query.Encode())
	}

	rec.body = `<?xml version="1.0" encoding="UTF-8"?>
<PolicyStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsPublic>true</IsPublic></PolicyStatus>`
	public, err := c.GetBucketPolicyStatus(ctx, "b1")
	if err != nil || !public {
		t.Errorf("public=%v err=%v", public, err)
	}
	if rec.last.Query.Encode() != "policyStatus=" {
		t.Errorf("query %q", rec.last.Query.Encode())
	}
}

func TestS3XMLErrorCarriesItsCode(t *testing.T) {
	rec := &recorder{status: 404, contentType: "application/xml", body: `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchPublicAccessBlockConfiguration</Code><Message>The public access block configuration was not found</Message></Error>`}
	c := newTestClient(t, rec, true)
	_, err := c.GetBucketPublicAccessBlock(context.Background(), "b1")
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v", err)
	}
	if ae.Code != "NoSuchPublicAccessBlockConfiguration" || !IsNotFound(err) ||
		ae.Message != "The public access block configuration was not found" {
		t.Errorf("got %+v", ae)
	}
}

func TestAssumeRoleWithWebIdentity(t *testing.T) {
	rec := &recorder{contentType: "text/xml", body: `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIA1</AccessKeyId><SecretAccessKey>sec</SecretAccessKey><SessionToken>tok</SessionToken><Expiration>2026-10-02T13:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:obio:sts::acme:assumed-role/ci/run-1</Arn><AssumedRoleId>ci:run-1</AssumedRoleId></AssumedRoleUser><SubjectFromWebIdentityToken>s</SubjectFromWebIdentityToken><Provider>https://idp</Provider><Audience>a</Audience></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`}
	// No keys: the exchange is what a workload does before it has any.
	c := newTestClient(t, rec, false)

	creds, err := c.AssumeRoleWithWebIdentity(context.Background(), AssumeRoleWithWebIdentityInput{
		RoleArn:          "arn:obio:iam::acme:role/ci",
		WebIdentityToken: "eyJ.a+b/c=",
		RoleSessionName:  "run-1",
		DurationSeconds:  900,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Credentials{
		AccessKeyID:     "ASIA1",
		SecretAccessKey: "sec",
		SessionToken:    "tok",
		Expiration:      time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC),
		AssumedRoleArn:  "arn:obio:sts::acme:assumed-role/ci/run-1",
	}
	if !reflect.DeepEqual(*creds, want) {
		t.Errorf("got %+v", *creds)
	}

	got := rec.last
	if got.Method != "POST" || got.Path != "/" || len(got.Query) != 0 {
		t.Errorf("sent %s %s?%s", got.Method, got.Path, got.Query.Encode())
	}
	// An Authorization header would route it to S3 instead of STS.
	if got.Header.Get("Authorization") != "" {
		t.Errorf("STS request is signed: %s", got.Header.Get("Authorization"))
	}
	if ct := got.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", ct)
	}
	form, err := url.ParseQuery(string(got.Body))
	if err != nil {
		t.Fatal(err)
	}
	wantForm := url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {"arn:obio:iam::acme:role/ci"}, "WebIdentityToken": {"eyJ.a+b/c="},
		"RoleSessionName": {"run-1"}, "DurationSeconds": {"900"},
	}
	if !reflect.DeepEqual(form, wantForm) {
		t.Errorf("form = %v", form)
	}
}

func TestSTSErrorMapsToAPIError(t *testing.T) {
	rec := &recorder{status: 400, contentType: "text/xml", body: `<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>InvalidIdentityToken</Code><Message>the token is not from an identity provider this role's scope trusts</Message></Error></ErrorResponse>`}
	c := newTestClient(t, rec, false)
	_, err := c.AssumeRoleWithWebIdentity(context.Background(), AssumeRoleWithWebIdentityInput{
		RoleArn: "arn:obio:iam::acme:role/ci", WebIdentityToken: "x", RoleSessionName: "s1",
	})
	var ae *APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v", err)
	}
	if ae.StatusCode != 400 || ae.Code != "InvalidIdentityToken" ||
		ae.Message != "the token is not from an identity provider this role's scope trusts" {
		t.Errorf("got %+v", ae)
	}
}

func TestEndpointOnlyClientRefusesSignedCalls(t *testing.T) {
	rec := &recorder{}
	c := newTestClient(t, rec, false)
	if _, err := c.ListUsers(context.Background()); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v, want ErrNoCredentials", err)
	}
	if rec.last.Method != "" {
		t.Error("a request was sent without credentials")
	}
	if _, err := New(Config{Endpoint: "http://x", AccessKey: "a"}); err == nil {
		t.Error("an access key without a secret should be refused")
	}
}

func TestPutOIDCProviderRefusesTheRedactedSecret(t *testing.T) {
	rec := &recorder{}
	c := newTestClient(t, rec, true)
	_, err := c.PutOIDCProvider(context.Background(), "kc", OIDCProvider{
		IssuerURL: "https://idp", ClientID: "c", ClientSecret: "********"})
	if err == nil || rec.last.Method != "" {
		t.Errorf("err=%v sent=%q", err, rec.last.Method)
	}
}

func TestOIDCProviderKeepsUnknownFields(t *testing.T) {
	// The console stores fields of its own; a read-modify-write through the
	// SDK must not drop them.
	in := `{"issuer_url":"https://idp","client_id":"c","enabled":false,"vendor":"entra","admin_roles":["a"]}`
	var p OIDCProvider
	if err := json.Unmarshal([]byte(in), &p); err != nil {
		t.Fatal(err)
	}
	if p.Enabled == nil || *p.Enabled || p.IssuerURL != "https://idp" || len(p.Extra) != 2 {
		t.Fatalf("got %+v", p)
	}
	out, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	jsonEqual(t, out, in)
}
