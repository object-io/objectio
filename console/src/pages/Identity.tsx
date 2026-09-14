import { useEffect, useState } from "react";
import { Shield, Plus, Trash2, CheckCircle, AlertCircle, Edit, Copy, Check } from "lucide-react";
import PageHeader from "../components/PageHeader";
import Card from "../components/Card";

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
        description={sessionTenant ? `OIDC provider for ${sessionTenant}` : "Manage OIDC identity providers"}
        action={
          <button
            onClick={() => startEdit()}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
          >
            <Plus size={16} /> Add Provider
          </button>
        }
      />

      {/* Editor */}
      {editing && (
        <Card title={editing === "__new__" ? "Add OIDC Provider" : `Edit: ${editing}`} className="mb-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Provider Name</label>
              <input
                value={providerName}
                onChange={(e) => setProviderName(e.target.value)}
                disabled={editing !== "__new__" || !!sessionTenant}
                placeholder="e.g. entra, keycloak, okta"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none disabled:bg-gray-100"
              />
              {sessionTenant && editing === "__new__" && (
                <p className="mt-1 text-xs text-gray-500">
                  Tenant-owned providers are auto-named <code>t-{sessionTenant.toLowerCase()}</code>.
                </p>
              )}
            </div>
            {/* The IdP needs this exact string registered as a redirect URI.
                It is server-derived and the same for every provider, so it is
                shown here rather than being an editable field. */}
            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-gray-500 mb-1">
                Redirect URI <span className="text-gray-400">(register this in your IdP)</span>
              </label>
              <div className="flex gap-2">
                <input
                  readOnly
                  value={callbackUrl || "unavailable"}
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm bg-gray-50 font-mono text-xs text-gray-700"
                />
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(callbackUrl);
                    setCopiedCallback(true);
                    setTimeout(() => setCopiedCallback(false), 2000);
                  }}
                  disabled={!callbackUrl}
                  className="px-3 py-2 bg-gray-100 rounded-lg text-sm font-medium hover:bg-gray-200 disabled:opacity-40"
                  title="Copy redirect URI"
                >
                  {copiedCallback ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
              {callbackIsDefault ? (
                <p className="mt-1 text-xs text-amber-700">
                  This is built from the gateway's bind address because
                  <code className="mx-1">--external-endpoint</code> is not set, so no
                  identity provider will accept it. Set it to the console's public URL
                  and restart the gateway before configuring SSO.
                </p>
              ) : (
                <p className="mt-1 text-xs text-gray-400">
                  One callback serves every provider and tenant — the provider and
                  tenant travel in the OAuth <code>state</code> parameter, not the URL.
                </p>
              )}
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Display Name</label>
              <input
                value={form.display_name}
                onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                placeholder="Corporate SSO"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            {/* For Microsoft the issuer is fully determined by the directory
                id (or the multi-tenant placeholder) below, so asking for it
                separately only creates two fields that can disagree — which is
                exactly how a wrong issuer survives until someone tries to log
                in. It is shown read-only instead. */}
            {form.vendor === "azure" ? (
              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-gray-500 mb-1">
                  Issuer URL{" "}
                  <span className="text-gray-400">— derived, not editable</span>
                </label>
                <input
                  readOnly
                  value={form.issuer_url || "set the directory ID below"}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm bg-gray-50 font-mono text-xs text-gray-600"
                />
              </div>
            ) : (
            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-gray-500 mb-1">Issuer URL</label>
              <div className="flex gap-2">
                <input
                  value={form.issuer_url}
                  onChange={(e) => setForm({ ...form, issuer_url: e.target.value })}
                  placeholder="https://login.microsoftonline.com/{tenant}/v2.0"
                  className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                />
                <button
                  onClick={testConnection}
                  className="px-3 py-2 bg-gray-100 rounded-lg text-sm font-medium hover:bg-gray-200"
                >
                  Test
                </button>
              </div>
              {testResult && (
                <p className={`mt-1 text-xs ${testResult.startsWith("Connected") ? "text-green-600" : testResult === "testing" ? "text-gray-400" : "text-red-600"}`}>
                  {testResult === "testing" ? "Testing connection..." : testResult}
                </p>
              )}
            </div>
            )}
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Client ID</label>
              <input
                value={form.client_id}
                onChange={(e) => setForm({ ...form, client_id: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Client Secret</label>
              <input
                type="password"
                value={form.client_secret}
                onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
                placeholder={editing !== "__new__" ? "********" : ""}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Audience</label>
              <input
                value={form.audience}
                onChange={(e) => setForm({ ...form, audience: e.target.value })}
                placeholder="Same as Client ID if empty"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Vendor</label>
              <select
                value={form.vendor}
                onChange={(e) => setForm({ ...form, vendor: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              >
                <option value="">Generic OIDC</option>
                <option value="azure">Microsoft Entra ID (Azure AD)</option>
                <option value="keycloak">Keycloak</option>
                <option value="okta">Okta</option>
                <option value="google">Google</option>
              </select>
            </div>
            {form.vendor === "azure" && (
              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-gray-500 mb-1">
                  Directory (tenant) ID{" "}
                  <span className="text-gray-400">— not the application ID</span>
                </label>
                <div className="flex gap-2">
                  <input
                    value={form.azure_tenant_id}
                    onChange={(e) => {
                      const tid = e.target.value.trim();
                      // This field used to be stored and ignored while the
                      // issuer was typed by hand, which is how a wrong issuer
                      // survives until someone tries to log in. Writing the
                      // issuer from it keeps the two from disagreeing.
                      setForm({
                        ...form,
                        azure_tenant_id: tid,
                        issuer_url: tid
                          ? `https://login.microsoftonline.com/${tid}/v2.0`
                          : form.issuer_url,
                      });
                    }}
                    placeholder="72f988bf-86f1-41af-91ab-2d7cd011db47  ·  or: organizations / common"
                    className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  />
                </div>
                <p className="mt-1 text-xs text-gray-400">
                  Sets the Issuer URL above. Use your Directory (tenant) ID from
                  Entra &rarr; Overview for a single organisation. Use{" "}
                  <code>organizations</code> only with Tenancy set to
                  &ldquo;multi-tenant&rdquo; below — it is the placeholder that
                  lets any work or school account sign in.
                </p>
              </div>
            )}

            {/* Tenancy ------------------------------------------------- */}
            <div className="md:col-span-2 border-t border-gray-200 pt-4 mt-1">
              <label className="block text-xs font-medium text-gray-500 mb-1">Tenancy</label>
              <select
                value={form.tenancy}
                onChange={(e) => setForm({ ...form, tenancy: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              >
                <option value="single">
                  Single tenant — this provider serves one ObjectIO tenant
                </option>
                <option value="multi">
                  Multi-tenant — each signing-in organisation gets its own tenant
                </option>
              </select>
              <p className="mt-1 text-xs text-gray-400">
                Multi-tenant keys on the <code>tid</code> claim: the first login
                from an organisation registers a tenant for it automatically.
              </p>
            </div>

            {form.tenancy === "multi" && (
              <>
                <div>
                  <label className="block text-xs font-medium text-gray-500 mb-1">
                    Quota per registered tenant (GB)
                  </label>
                  <input
                    type="number"
                    min="0"
                    step="0.5"
                    value={quotaGbStr}
                    onChange={(e) => setQuotaGbStr(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  />
                  <p className="mt-1 text-xs text-gray-400">
                    Applied at registration; raise it per tenant afterwards. 0 = unlimited.
                  </p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-500 mb-1">
                    Tenant admin role
                  </label>
                  <input
                    value={form.tenant_admin_role}
                    onChange={(e) =>
                      setForm({ ...form, tenant_admin_role: e.target.value })
                    }
                    placeholder="objectio-admin"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  />
                  <p className="mt-1 text-xs text-gray-400">
                    A user whose token carries this role administers their own
                    tenant. Leave empty and only you can manage them.
                  </p>
                </div>
                <div className="md:col-span-2">
                  <label className="block text-xs font-medium text-gray-500 mb-1">
                    Allowed directory IDs{" "}
                    <span className="text-gray-400">(optional)</span>
                  </label>
                  <input
                    value={allowedTidsStr}
                    onChange={(e) => setAllowedTidsStr(e.target.value)}
                    placeholder="leave empty to let any organisation register"
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm font-mono text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  />
                  <p className="mt-1 text-xs text-amber-700">
                    Empty means open registration: any Microsoft work or school
                    account anywhere can sign in and be given a tenant. List
                    directory IDs here to restrict it.
                  </p>
                </div>
              </>
            )}
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Groups Claim</label>
              <input
                value={form.claim_name}
                onChange={(e) => setForm({ ...form, claim_name: e.target.value })}
                placeholder="groups"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1">Scopes</label>
              <input
                value={form.scopes}
                onChange={(e) => setForm({ ...form, scopes: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-xs font-medium text-gray-500 mb-1">Admin Roles (comma-separated group/role IDs)</label>
              <input
                value={adminRolesStr}
                onChange={(e) => setAdminRolesStr(e.target.value)}
                placeholder="e.g. 0d35f722-797c-46ec-8360-8dc018c81e09"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none"
              />
            </div>
            <div className="md:col-span-2 flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                className="rounded"
              />
              <label className="text-sm">Enabled</label>
            </div>
            {!sessionTenant && (
              <div className="md:col-span-2 flex items-start gap-2">
                <input
                  id="system_admin_chk"
                  type="checkbox"
                  checked={form.system_admin ?? false}
                  onChange={(e) =>
                    setForm({ ...form, system_admin: e.target.checked })
                  }
                  className="rounded mt-1"
                />
                <label htmlFor="system_admin_chk" className="text-sm">
                  Allow system-admin SSO
                  <span className="block text-xs text-gray-500 mt-0.5">
                    Users authenticated through this provider log into the
                    system-admin console without a tenant binding. Leave
                    unchecked if this provider is only for tenant users.
                  </span>
                </label>
              </div>
            )}
          </div>
          <div className="flex gap-3 mt-6 pt-4 border-t border-gray-100">
            <button
              onClick={save}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
            >
              Save
            </button>
            <button
              onClick={() => setEditing(null)}
              className="px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-200"
            >
              Cancel
            </button>
          </div>
        </Card>
      )}

      {/* Provider list */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 border-b border-gray-200">
            <tr>
              <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Provider</th>
              <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Issuer</th>
              <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Client ID</th>
              <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="text-right px-6 py-3 text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {loading ? (
              <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-400">Loading...</td></tr>
            ) : visibleProviders.length === 0 ? (
              <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-400">No OIDC providers configured</td></tr>
            ) : (
              visibleProviders.map((p) => (
                <tr key={p.key} className="hover:bg-gray-50">
                  <td className="px-6 py-3">
                    <div className="flex items-center gap-2">
                      <Shield size={16} className="text-blue-500" />
                      <div>
                        <span className="font-medium">{p.value.display_name || p.key.replace("identity/openid/", "")}</span>
                        <span className="text-gray-400 ml-2 text-xs">{p.value.vendor || "oidc"}</span>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-3 text-gray-500 truncate max-w-xs">{p.value.issuer_url}</td>
                  <td className="px-6 py-3 font-mono text-xs text-gray-500">{p.value.client_id}</td>
                  <td className="px-6 py-3">
                    {p.value.enabled ? (
                      <span className="inline-flex items-center gap-1 text-green-700 text-xs">
                        <CheckCircle size={14} /> Enabled
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-gray-400 text-xs">
                        <AlertCircle size={14} /> Disabled
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-3 text-right">
                    <button onClick={() => startEdit(p)} className="text-blue-500 hover:text-blue-700 p-1">
                      <Edit size={16} />
                    </button>
                    <button onClick={() => remove(p.key)} className="text-red-500 hover:text-red-700 p-1 ml-2">
                      <Trash2 size={16} />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
