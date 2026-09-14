import { useEffect, useState } from "react";
import { Shield, Plus, Trash2, Edit, Copy, Check } from "lucide-react";
import PageHeader from "../components/PageHeader";
import {
  Badge,
  Banner,
  Button,
  Card,
  Input,
  Select,
  Table,
  Row,
  Cell,
} from "../components/ui";

interface OidcProvider {
  key: string;
  value: {
    issuer_url: string;
    client_id: string;
    client_secret: string;
    audience: string;
    claim_name: string;
    role_claim: string;
    scopes: string;
    admin_roles: string[];
    display_name: string;
    enabled: boolean;
    vendor?: string;
    azure_tenant_id?: string;
    /// Allow this provider to log users into the system-admin console
    /// (no tenant binding required). Defaults to false — tenant-scoped.
    system_admin?: boolean;
    tenancy?: string;
    tenant_admin_role?: string;
    tenant_quota_bytes?: number;
    allowed_tids?: string[];
  };
  updated_at: number;
  updated_by: string;
}

const emptyProvider = {
  issuer_url: "",
  client_id: "",
  client_secret: "",
  audience: "",
  claim_name: "groups",
  role_claim: "role",
  scopes: "openid profile email",
  admin_roles: [] as string[],
  display_name: "",
  enabled: true,
  vendor: "",
  azure_tenant_id: "",
  system_admin: false,
  // Tenancy. "single" binds the provider to one tenant; "multi" follows the
  // upstream tenant in the token and registers it on first login.
  tenancy: "single",
  tenant_admin_role: "",
  tenant_quota_bytes: 2 * 1024 * 1024 * 1024,
  allowed_tids: [] as string[],
};

/** 2 GiB, matching DEFAULT_SELF_REGISTERED_QUOTA_BYTES on the gateway. */
const DEFAULT_TENANT_QUOTA_BYTES = 2 * 1024 * 1024 * 1024;

export default function Identity() {
  const [providers, setProviders] = useState<OidcProvider[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState(emptyProvider);
  const [providerName, setProviderName] = useState("");
  const [adminRolesStr, setAdminRolesStr] = useState("");
  const [allowedTidsStr, setAllowedTidsStr] = useState("");
  const [quotaGbStr, setQuotaGbStr] = useState("2");
  const [testResult, setTestResult] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionTenant, setSessionTenant] = useState("");
  const [tenantOidcProvider, setTenantOidcProvider] = useState("");
  // The redirect URI the gateway will actually send. It is derived from the
  // gateway's --external-endpoint and is identical for every provider, so it
  // is shown to be copied into the IdP rather than edited here.
  const [callbackUrl, setCallbackUrl] = useState("");
  const [callbackIsDefault, setCallbackIsDefault] = useState(false);
  const [copiedCallback, setCopiedCallback] = useState(false);
  // No synchronous `setLoading(true)`: the initial state already covers the
  // mount path, and a refresh updating in place reads better than flashing
  // a spinner over data already on screen.

  const load = () => {

    // Get session tenant
    fetch("/_console/api/session")
      .then((r) => r.json())
      .then((d) => {
        setSessionTenant(d.tenant || "");
        // If tenant user, get their tenant's oidc_provider name
        if (d.tenant) {
          fetch(`/_admin/tenants/${d.tenant}`)
            .then((r) => r.json())
            .then((t) => setTenantOidcProvider(t.oidc_provider || ""))
            .catch(() => {});
        }
      })
      .catch(() => {});

    // Load all OIDC providers
    fetch("/_console/api/oidc/enabled")
      .then((r) => r.json())
      .then((d) => {
        setCallbackUrl(d.callback_url || "");
        setCallbackIsDefault(Boolean(d.callback_url_is_default));
      })
      .catch(() => {
        /* non-fatal: the form still works, it just cannot show the URI */
      });

    fetch("/_admin/config?prefix=identity%2Fopenid")
      .then((r) => r.json())
      .then((all: OidcProvider[]) => {
        setProviders(all);
      })
      .catch(() => setProviders([]))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  // Filter providers: system admin sees all, tenant user sees only their assigned provider
  const visibleProviders = sessionTenant
    ? providers.filter((p) => {
        const name = p.key.replace("identity/openid/", "");
        return name === tenantOidcProvider;
      })
    : providers;

  const startEdit = (p?: OidcProvider) => {
    if (p) {
      const name = p.key.replace("identity/openid/", "");
      setProviderName(name);
      setForm({ ...emptyProvider, ...p.value });
      setAdminRolesStr(p.value.admin_roles?.join(", ") || "");
      setAllowedTidsStr(p.value.allowed_tids?.join(", ") || "");
      setQuotaGbStr(
        String(
          (p.value.tenant_quota_bytes ?? DEFAULT_TENANT_QUOTA_BYTES) /
            (1024 * 1024 * 1024)
        )
      );
      setEditing(name);
    } else {
      // Tenant admins own exactly the slug `t-{tenant}`; system admin
      // can pick any name.
      setProviderName(sessionTenant ? `t-${sessionTenant.toLowerCase()}` : "");
      setForm({ ...emptyProvider });
      setAdminRolesStr("");
      setAllowedTidsStr("");
      setQuotaGbStr("2");
      setEditing("__new__");
    }
    setTestResult(null);
  };

  const save = async () => {
    if (!providerName.trim()) return;
    const gb = Number.parseFloat(quotaGbStr);
    const payload = {
      ...form,
      admin_roles: adminRolesStr.split(",").map((s) => s.trim()).filter(Boolean),
      // Empty list = open registration, which is what a `common` endpoint
      // implies. Populating it restricts self-registration to those tenants.
      allowed_tids: allowedTidsStr.split(",").map((s) => s.trim()).filter(Boolean),
      // Stored in bytes; entered in GB because that is how a quota is discussed.
      tenant_quota_bytes: Number.isFinite(gb)
        ? Math.round(gb * 1024 * 1024 * 1024)
        : DEFAULT_TENANT_QUOTA_BYTES,
    };
    // For tenant admins, the gateway auto-binds tenant.oidc_provider when
    // the slug `identity/openid/t-{tenant}` is PUT, so no separate
    // tenant-update call is required.
    await fetch(`/_admin/config/identity/openid/${providerName}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    setEditing(null);
    load();
  };

  const remove = async (key: string) => {
    const name = key.replace("identity/openid/", "");
    if (!confirm(`Delete OIDC provider "${name}"?`)) return;
    await fetch(`/_admin/config/${key}`, { method: "DELETE" });
    load();
  };

  const testConnection = async () => {
    setTestResult("testing");
    try {
      const url = form.issuer_url.replace(/\/$/, "") + "/.well-known/openid-configuration";
      const r = await fetch(url);
      if (r.ok) {
        const doc = await r.json();
        setTestResult(`Connected. Token endpoint: ${doc.token_endpoint}`);
      } else {
        setTestResult(`Failed: ${r.status} ${r.statusText}`);
      }
    } catch (e) {
      setTestResult(`Error: ${e}`);
    }
  };

  return (
    <div className="p-6">
      <PageHeader
        title="Identity"
        description={
          sessionTenant
            ? `OIDC provider for ${sessionTenant}`
            : "OIDC providers that can sign users into this console"
        }
        action={
          <Button variant="primary" icon={<Plus size={13} />} onClick={() => startEdit()}>
            Add provider
          </Button>
        }
      />

      {editing && (
        <Card
          title={editing === "__new__" ? "Add OIDC provider" : `Edit · ${editing}`}
          className="mb-4"
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Input
              label="Provider name"
              value={providerName}
              onChange={(e) => setProviderName(e.target.value)}
              disabled={editing !== "__new__" || !!sessionTenant}
              placeholder="entra, keycloak, okta"
              hint={
                sessionTenant && editing === "__new__"
                  ? `Tenant-owned providers are auto-named t-${sessionTenant.toLowerCase()}`
                  : undefined
              }
            />
            <Input
              label="Display name"
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              placeholder="Corporate SSO"
            />

            {/* The IdP needs this exact string registered as a redirect URI.
                It is server-derived and identical for every provider, so it is
                shown rather than typed. */}
            <div className="md:col-span-2">
              <label className="block text-[11px] font-semibold text-text-2 mb-1">
                Redirect URI <span className="font-normal text-faint">— register this in your IdP</span>
              </label>
              <div className="flex gap-2">
                <input
                  readOnly
                  value={callbackUrl || "unavailable"}
                  className="flex-1 h-8 px-2.5 bg-surface-2 text-text-2 border border-border-strong
                    rounded-control font-mono text-[12px]"
                />
                <Button
                  icon={copiedCallback ? <Check size={13} /> : <Copy size={13} />}
                  disabled={!callbackUrl}
                  onClick={() => {
                    navigator.clipboard.writeText(callbackUrl);
                    setCopiedCallback(true);
                    setTimeout(() => setCopiedCallback(false), 2000);
                  }}
                >
                  {copiedCallback ? "Copied" : "Copy"}
                </Button>
              </div>
              {callbackIsDefault ? (
                <Banner kind="warn" className="mt-2" title="No identity provider will accept this URI">
                  It is built from the gateway's bind address because{" "}
                  <code>--external-endpoint</code> is not set. Point that at the
                  console's public URL and restart the gateway before configuring SSO.
                </Banner>
              ) : (
                <p className="mt-1 text-[11px] text-faint">
                  One callback serves every provider and tenant — both travel in the
                  OAuth <code>state</code> parameter, not the URL.
                </p>
              )}
            </div>

            <Select
              label="Vendor"
              value={form.vendor}
              onChange={(e) => setForm({ ...form, vendor: e.target.value })}
            >
              <option value="">Generic OIDC</option>
              <option value="azure">Microsoft Entra ID (Azure AD)</option>
              <option value="keycloak">Keycloak</option>
              <option value="okta">Okta</option>
              <option value="google">Google</option>
            </Select>

            {form.vendor === "azure" ? (
              <>
                <Input
                  label={
                    <>
                      Directory (tenant) ID{" "}
                      <span className="font-normal text-faint">— not the application ID</span>
                    </>
                  }
                  value={form.azure_tenant_id}
                  className="font-mono text-[12px]"
                  placeholder="72f988bf-… · or organizations / common"
                  onChange={(e) => {
                    const tid = e.target.value.trim();
                    // This field used to be stored and ignored while the issuer
                    // was typed by hand, which is how a wrong issuer survives
                    // until someone tries to log in. Writing the issuer from it
                    // keeps the two from disagreeing.
                    setForm({
                      ...form,
                      azure_tenant_id: tid,
                      issuer_url: tid
                        ? `https://login.microsoftonline.com/${tid}/v2.0`
                        : form.issuer_url,
                    });
                  }}
                  hint="organizations only makes sense with multi-tenant below — it is the placeholder that lets any work or school account sign in."
                />
                <div className="md:col-span-2">
                  <label className="block text-[11px] font-semibold text-text-2 mb-1">
                    Issuer URL <span className="font-normal text-faint">— derived, not editable</span>
                  </label>
                  <input
                    readOnly
                    value={form.issuer_url || "set the directory ID above"}
                    className="w-full h-8 px-2.5 bg-surface-2 text-text-2 border border-border-strong
                      rounded-control font-mono text-[12px]"
                  />
                </div>
              </>
            ) : (
              <div className="md:col-span-2">
                <label className="block text-[11px] font-semibold text-text-2 mb-1">Issuer URL</label>
                <div className="flex gap-2">
                  <input
                    value={form.issuer_url}
                    onChange={(e) => setForm({ ...form, issuer_url: e.target.value })}
                    placeholder="https://login.example.com/realms/main"
                    className="flex-1 h-8 px-2.5 bg-surface text-text border border-border-strong
                      rounded-control text-[13px] placeholder:text-faint
                      focus:outline-none focus:border-accent focus:ring-2 focus:ring-accent-soft"
                  />
                  <Button onClick={testConnection}>Test</Button>
                </div>
                {testResult && (
                  <p
                    className={`mt-1 text-[11px] ${
                      testResult.startsWith("Connected")
                        ? "text-ok"
                        : testResult === "testing"
                          ? "text-faint"
                          : "text-err"
                    }`}
                  >
                    {testResult === "testing" ? "Testing connection…" : testResult}
                  </p>
                )}
              </div>
            )}

            <Input
              label="Client ID"
              value={form.client_id}
              onChange={(e) => setForm({ ...form, client_id: e.target.value })}
            />
            <Input
              label="Client secret"
              type="password"
              value={form.client_secret}
              onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
              placeholder={editing !== "__new__" ? "••••••••" : ""}
              hint="The secret value, not the secret ID — Entra shows the ID next to it and they look alike."
            />
            <Input
              label="Audience"
              value={form.audience}
              onChange={(e) => setForm({ ...form, audience: e.target.value })}
              placeholder="Same as Client ID if empty"
            />
            <Input
              label="Scopes"
              value={form.scopes}
              onChange={(e) => setForm({ ...form, scopes: e.target.value })}
            />

            <div className="md:col-span-2 border-t border-border pt-3 mt-1">
              <Select
                label="Tenancy"
                value={form.tenancy}
                onChange={(e) => setForm({ ...form, tenancy: e.target.value })}
                hint="Multi-tenant keys on the tid claim: the first login from an organisation registers a tenant for it automatically."
              >
                <option value="single">Single tenant — this provider serves one ObjectIO tenant</option>
                <option value="multi">Multi-tenant — each signing-in organisation gets its own tenant</option>
              </Select>
            </div>

            {form.tenancy === "multi" && (
              <>
                <Input
                  label="Quota per registered tenant (GB)"
                  type="number"
                  min="0"
                  step="0.5"
                  value={quotaGbStr}
                  onChange={(e) => setQuotaGbStr(e.target.value)}
                  hint="Applied at registration; raise it per tenant afterwards. 0 = unlimited."
                />
                <Input
                  label="Tenant admin role"
                  value={form.tenant_admin_role}
                  onChange={(e) => setForm({ ...form, tenant_admin_role: e.target.value })}
                  placeholder="objectio-admin"
                  hint="A user whose token carries this role administers their own tenant. Empty means only you can."
                />
                <div className="md:col-span-2">
                  <Input
                    label={
                      <>
                        Allowed directory IDs{" "}
                        <span className="font-normal text-faint">(optional)</span>
                      </>
                    }
                    value={allowedTidsStr}
                    onChange={(e) => setAllowedTidsStr(e.target.value)}
                    placeholder="leave empty to let any organisation register"
                    className="font-mono text-[12px]"
                  />
                  {!allowedTidsStr.trim() && (
                    <Banner kind="warn" className="mt-2" title="Open registration">
                      Any Microsoft work or school account, anywhere, can sign in and
                      be given a tenant. List directory IDs to restrict it.
                    </Banner>
                  )}
                </div>
              </>
            )}

            <Input
              label="Groups claim"
              value={form.claim_name}
              onChange={(e) => setForm({ ...form, claim_name: e.target.value })}
              placeholder="groups"
            />
            <Input
              label="Admin roles"
              value={adminRolesStr}
              onChange={(e) => setAdminRolesStr(e.target.value)}
              placeholder="0d35f722-797c-46ec-8360-8dc018c81e09"
              hint="Comma-separated group or role IDs."
            />

            <div className="md:col-span-2 flex flex-col gap-2 border-t border-border pt-3">
              <label className="flex items-center gap-2 text-[12px] text-text-2">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                  className="accent-[var(--oio-accent)]"
                />
                Enabled
              </label>
              {!sessionTenant && (
                <label className="flex items-start gap-2 text-[12px] text-text-2">
                  <input
                    type="checkbox"
                    checked={form.system_admin ?? false}
                    onChange={(e) => setForm({ ...form, system_admin: e.target.checked })}
                    className="accent-[var(--oio-accent)] mt-0.5"
                  />
                  <span>
                    Allow system-admin SSO
                    <span className="block text-[11px] text-muted mt-0.5">
                      Users from this provider sign into the system-admin console with
                      no tenant binding. Leave unchecked for a tenant-only provider.
                    </span>
                  </span>
                </label>
              )}
            </div>
          </div>

          <div className="flex gap-2 mt-4 pt-3 border-t border-border">
            <Button variant="primary" onClick={save}>
              Save
            </Button>
            <Button onClick={() => setEditing(null)}>Cancel</Button>
          </div>
        </Card>
      )}

      <Table
        columns={[
          { key: "provider", label: "Provider" },
          { key: "issuer", label: "Issuer" },
          { key: "client", label: "Client ID", className: "w-72" },
          { key: "tenancy", label: "Tenancy", className: "w-32" },
          { key: "status", label: "Status", className: "w-32" },
          { key: "actions", label: "", className: "w-24" },
        ]}
        loading={loading}
        empty="No OIDC providers configured"
        footer={
          visibleProviders.length
            ? `${visibleProviders.length} provider${visibleProviders.length === 1 ? "" : "s"} · ${
                visibleProviders.filter((p) => p.value.enabled).length
              } enabled`
            : undefined
        }
      >
        {visibleProviders.length
          ? visibleProviders.map((p) => (
              <Row key={p.key}>
                <Cell>
                  <span className="flex items-center gap-2">
                    <Shield size={14} className="text-muted shrink-0" />
                    <span className="flex flex-col min-w-0">
                      <span className="text-[13px] font-medium text-text truncate">
                        {p.value.display_name || p.key.replace("identity/openid/", "")}
                      </span>
                      <span className="font-mono text-[11px] text-muted truncate">
                        {p.value.vendor || "oidc"}
                      </span>
                    </span>
                  </span>
                </Cell>
                <Cell className="font-mono text-[11px] max-w-xs truncate">
                  {p.value.issuer_url}
                </Cell>
                <Cell className="font-mono text-[11px] truncate">{p.value.client_id}</Cell>
                <Cell>
                  {/* Multi-tenant is the setting that decides whether a stranger
                      can self-register, so it belongs in the list rather than
                      two clicks into the form. */}
                  <Badge kind={p.value.tenancy === "multi" ? "info" : "neutral"}>
                    {p.value.tenancy === "multi" ? "multi" : "single"}
                  </Badge>
                </Cell>
                <Cell>
                  <Badge kind={p.value.enabled ? "ok" : "neutral"}>
                    {p.value.enabled ? "Enabled" : "Disabled"}
                  </Badge>
                </Cell>
                <Cell align="right">
                  <span className="inline-flex items-center gap-0.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                    <button
                      onClick={() => startEdit(p)}
                      title="Edit provider"
                      className="p-1 rounded text-muted hover:text-text hover:bg-surface-2"
                    >
                      <Edit size={13} />
                    </button>
                    <button
                      onClick={() => remove(p.key)}
                      title="Delete provider"
                      className="p-1 rounded text-muted hover:text-err hover:bg-surface-2"
                    >
                      <Trash2 size={13} />
                    </button>
                  </span>
                </Cell>
              </Row>
            ))
          : undefined}
      </Table>
    </div>
  );
}
