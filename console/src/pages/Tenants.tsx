import { useCallback, useEffect, useState } from "react";
import {
  Building2,
  Plus,
  Trash2,
  Settings2,
  Users,
  UserPlus,
  X,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import {
  Badge,
  Banner,
  Button,
  CapacityBar,
  Card,
  ChartCard,
  Chip,
  Input,
  Table,
  Row,
  Cell,
} from "../components/ui";

interface Tenant {
  name: string;
  display_name: string;
  default_pool: string;
  allowed_pools: string[];
  quota_bytes: number;
  quota_buckets: number;
  quota_objects: number;
  admin_users: string[];
  oidc_provider: string;
  labels: Record<string, string>;
  enabled: boolean;
  created_at: number;
}

interface TenantUser {
  user_id: string;
  display_name: string;
  arn: string;
  tenant: string;
}

interface AdminBucket {
  name: string;
  tenant?: string;
}

const emptyTenant = {
  name: "",
  display_name: "",
  default_pool: "",
  allowed_pools: [] as string[],
  quota_bytes: 0,
  quota_buckets: 0,
  quota_objects: 0,
  admin_users: [] as string[],
  oidc_provider: "",
  labels: {} as Record<string, string>,
  enabled: true,
};

const QUOTA_CHOICES = [
  { bytes: 0, label: "Unlimited" },
  { bytes: 2 * 1024 ** 3, label: "2 GB" },
  { bytes: 100 * 1024 ** 3, label: "100 GB" },
  { bytes: 500 * 1024 ** 3, label: "500 GB" },
  { bytes: 1024 ** 4, label: "1 TB" },
  { bytes: 10 * 1024 ** 4, label: "10 TB" },
  { bytes: 50 * 1024 ** 4, label: "50 TB" },
];

function formatBytes(b: number): string {
  if (!b) return "∞";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
  const n = b / 1024 ** i;
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

export default function Tenants() {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [pools, setPools] = useState<string[]>([]);
  const [bucketsByTenant, setBucketsByTenant] = useState<Record<string, number>>({});
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState(emptyTenant);
  const [allowedPoolsStr, setAllowedPoolsStr] = useState("");
  const [loading, setLoading] = useState(true);
  const [managingAdmins, setManagingAdmins] = useState<string | null>(null);
  const [tenantUsers, setTenantUsers] = useState<TenantUser[]>([]);
  const [adminInput, setAdminInput] = useState("");
  const [adminError, setAdminError] = useState("");

  const load = useCallback(() => {
    Promise.all([
      fetch("/_admin/tenants").then((r) => r.json()).catch(() => []),
      fetch("/_admin/pools").then((r) => r.json()).catch(() => []),
      fetch("/_admin/buckets").then((r) => r.json()).catch(() => ({ buckets: [] })),
    ])
      .then(([t, p, b]) => {
        setTenants(Array.isArray(t) ? t : t.tenants || []);
        const rawPools = Array.isArray(p) ? p : p.pools || [];
        setPools(rawPools.map((pool: { name: string }) => pool.name));
        // The bucket count per tenant is not on the tenant record, but every
        // bucket carries its tenant — so count them here rather than adding a
        // round trip per row.
        const counts: Record<string, number> = {};
        for (const bk of (b.buckets || []) as AdminBucket[]) {
          const key = bk.tenant || "";
          counts[key] = (counts[key] ?? 0) + 1;
        }
        setBucketsByTenant(counts);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const startEdit = (t?: Tenant) => {
    if (t) {
      setForm({ ...emptyTenant, ...t });
      setAllowedPoolsStr(t.allowed_pools?.join(", ") || "");
      setEditing(t.name);
    } else {
      setForm({ ...emptyTenant });
      setAllowedPoolsStr("");
      setEditing("__new__");
    }
  };

  const save = async () => {
    // admin_users is managed in its own panel — carry the current value
    // through so saving the form does not silently drop the tenant's admins.
    const current = tenants.find((t) => t.name === form.name);
    const payload = {
      ...form,
      allowed_pools: allowedPoolsStr.split(",").map((s) => s.trim()).filter(Boolean),
      admin_users: current?.admin_users || form.admin_users || [],
    };
    const method = editing === "__new__" ? "POST" : "PUT";
    const url = editing === "__new__" ? "/_admin/tenants" : `/_admin/tenants/${form.name}`;
    await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setEditing(null);
    load();
  };

  const remove = async (name: string) => {
    if (!confirm(`Delete tenant "${name}"? All buckets must be removed first.`)) return;
    const r = await fetch(`/_admin/tenants/${name}`, { method: "DELETE" });
    if (!r.ok) alert(await r.text());
    load();
  };

  const openAdmins = async (name: string) => {
    setManagingAdmins(name);
    setAdminInput("");
    setAdminError("");
    try {
      const r = await fetch("/_admin/users");
      const d = await r.json();
      setTenantUsers((d.users || []).filter((u: TenantUser) => u.tenant === name));
    } catch {
      setTenantUsers([]);
    }
  };

  const addAdmin = async (entry: string) => {
    const val = entry.trim();
    if (!val) return;
    setAdminError("");
    const r = await fetch(`/_admin/tenants/${managingAdmins}/admins`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(val.startsWith("arn:") ? { user_arn: val } : { user_id: val }),
    });
    if (!r.ok) {
      setAdminError(await r.text());
      return;
    }
    setAdminInput("");
    load();
  };

  const removeAdmin = async (entry: string) => {
    if (!confirm(`Remove ${entry} from ${managingAdmins} admins?`)) return;
    const r = await fetch(
      `/_admin/tenants/${managingAdmins}/admins/${encodeURIComponent(entry)}`,
      { method: "DELETE" }
    );
    if (!r.ok) {
      setAdminError(await r.text());
      return;
    }
    load();
  };

  const managingTenant = tenants.find((t) => t.name === managingAdmins);
  const totalQuota = tenants.reduce((a, t) => a + t.quota_bytes, 0);
  const unlimited = tenants.filter((t) => !t.quota_bytes).length;

  return (
    <div className="p-6">
      <PageHeader
        title="Tenants"
        description="Multi-tenant isolation — each tenant gets its own buckets, quotas and identity"
        action={
          <Button variant="primary" icon={<Plus size={13} />} onClick={() => startEdit()}>
            Create tenant
          </Button>
        }
      />

      <div className="grid lg:grid-cols-2 gap-4 mb-4">
        <ChartCard title="Storage by tenant" subtitle="used bytes over time">
          <NeedsSeries
            metric="objectio_tenant_used_bytes"
            reason="Nothing accounts for storage per tenant yet. Bucket and object
              records carry a tenant, but nothing sums them into a usage figure,
              so there is no series for Prometheus to keep history of."
          />
        </ChartCard>
        <ChartCard title="Requests by tenant" subtitle="requests per hour">
          <NeedsSeries
            metric="objectio_s3_requests_total{tenant=…}"
            reason="The S3 request counter is labelled by operation and status but
              not by tenant, so requests cannot be split per tenant. The counter
              is recorded in the metrics middleware, which runs before the auth
              layer resolves who the caller is."
          />
        </ChartCard>
      </div>

      {managingAdmins && managingTenant && (
        <Card
          title={`Tenant admins · ${managingTenant.display_name || managingAdmins}`}
          action={
            <Button variant="ghost" size="sm" onClick={() => setManagingAdmins(null)}>
              Close
            </Button>
          }
          className="mb-4"
        >
          <p className="text-[11px] text-muted mb-3">
            Tenant admins manage users, access keys, buckets, warehouses and shares{" "}
            <em>within this tenant only</em>. They cannot reach other tenants or
            system-level resources.
          </p>

          {managingTenant.admin_users.length === 0 ? (
            <Banner kind="warn" className="mb-3">
              No tenant admins. Only the system admin can manage this tenant until
              one is added.
            </Banner>
          ) : (
            <ul className="space-y-1 mb-3">
              {managingTenant.admin_users.map((u) => {
                const user = tenantUsers.find((tu) => tu.user_id === u || tu.arn === u);
                return (
                  <li
                    key={u}
                    className="flex items-center justify-between px-2.5 py-1.5 bg-surface-2 rounded-control"
                  >
                    <span className="flex flex-col min-w-0">
                      <span className="text-[12px] font-medium text-text truncate">
                        {user?.display_name || u}
                      </span>
                      <span className="text-[10px] text-faint font-mono truncate">{u}</span>
                    </span>
                    <button
                      onClick={() => void removeAdmin(u)}
                      className="text-faint hover:text-err p-1"
                      title="Remove admin"
                    >
                      <X size={14} />
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <label className="block text-[11px] font-semibold text-text-2 mb-1">
                Add from this tenant
              </label>
              <select
                value=""
                onChange={(e) => e.target.value && void addAdmin(e.target.value)}
                className="w-full h-8 px-2.5 bg-surface text-text border border-border-strong
                  rounded-control text-[13px] focus:outline-none focus:border-accent"
              >
                <option value="">— Pick a tenant user —</option>
                {tenantUsers
                  .filter((u) => !managingTenant.admin_users.includes(u.user_id))
                  .map((u) => (
                    <option key={u.user_id} value={u.user_id}>
                      {u.display_name} ({u.user_id})
                    </option>
                  ))}
              </select>
            </div>
            <div className="flex-1">
              <Input
                label="or by id / ARN"
                value={adminInput}
                onChange={(e) => setAdminInput(e.target.value)}
                placeholder="user_id or user ARN"
              />
            </div>
            <Button
              variant="accent"
              icon={<UserPlus size={13} />}
              disabled={!adminInput.trim()}
              onClick={() => void addAdmin(adminInput)}
            >
              Add
            </Button>
          </div>
          {adminError && (
            <Banner kind="err" className="mt-3">
              {adminError}
            </Banner>
          )}
        </Card>
      )}

      {editing && (
        <Card
          title={editing === "__new__" ? "Create tenant" : `Edit · ${editing}`}
          className="mb-4"
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Input
              label="Tenant name"
              value={form.name}
              disabled={editing !== "__new__"}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="acme-corp"
              hint={editing === "__new__" ? "Lowercase, used in ARNs" : undefined}
            />
            <Input
              label="Display name"
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              placeholder="Acme Corporation"
            />
            <div>
              <label className="block text-[11px] font-semibold text-text-2 mb-1">
                Default pool
              </label>
              <select
                value={form.default_pool}
                onChange={(e) => setForm({ ...form, default_pool: e.target.value })}
                className="w-full h-8 px-2.5 bg-surface text-text border border-border-strong
                  rounded-control text-[13px] focus:outline-none focus:border-accent"
              >
                <option value="">System default</option>
                {pools.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
            <Input
              label="Allowed pools"
              value={allowedPoolsStr}
              onChange={(e) => setAllowedPoolsStr(e.target.value)}
              placeholder="default, archive"
              hint="Comma separated; blank means the default pool only"
            />
            <div>
              <label className="block text-[11px] font-semibold text-text-2 mb-1">
                Storage quota
              </label>
              <select
                value={form.quota_bytes}
                onChange={(e) => setForm({ ...form, quota_bytes: Number(e.target.value) })}
                className="w-full h-8 px-2.5 bg-surface text-text border border-border-strong
                  rounded-control text-[13px] focus:outline-none focus:border-accent"
              >
                {QUOTA_CHOICES.map((q) => (
                  <option key={q.bytes} value={q.bytes}>
                    {q.label}
                  </option>
                ))}
              </select>
            </div>
            <Input
              label="Max buckets"
              type="number"
              value={form.quota_buckets}
              onChange={(e) => setForm({ ...form, quota_buckets: Number(e.target.value) })}
              hint="0 = unlimited"
            />
            <Input
              label="OIDC provider"
              value={form.oidc_provider}
              onChange={(e) => setForm({ ...form, oidc_provider: e.target.value })}
              placeholder="entra"
              hint="Name of a configured provider; blank means password login"
            />
            <div className="flex items-end">
              <label className="flex items-center gap-2 text-[12px] text-text-2 h-8">
                <input
                  type="checkbox"
                  checked={form.enabled}
                  onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
                  className="accent-[var(--oio-accent)]"
                />
                Enabled
              </label>
            </div>
          </div>
          <div className="flex gap-2 mt-4 pt-3 border-t border-border">
            <Button variant="primary" onClick={() => void save()}>
              Save
            </Button>
            <Button onClick={() => setEditing(null)}>Cancel</Button>
          </div>
        </Card>
      )}

      <Table
        columns={[
          { key: "tenant", label: "Tenant" },
          { key: "pool", label: "Pool", className: "w-40" },
          { key: "quota", label: "Quota", className: "w-64" },
          { key: "buckets", label: "Buckets", align: "right", className: "w-24" },
          { key: "oidc", label: "OIDC", className: "w-32" },
          { key: "admins", label: "Admins", align: "right", className: "w-24" },
          { key: "status", label: "Status", className: "w-32" },
          { key: "actions", label: "", className: "w-28" },
        ]}
        loading={loading}
        empty="No tenants configured"
        footer={
          tenants.length
            ? `${tenants.length} tenant${tenants.length === 1 ? "" : "s"} · ${formatBytes(
                totalQuota
              )} of quota allocated${unlimited ? ` · ${unlimited} unlimited` : ""}`
            : undefined
        }
      >
        {tenants.length
          ? tenants.map((t) => (
              <Row key={t.name}>
                <Cell>
                  <span className="flex items-center gap-2">
                    <Building2 size={14} className="text-muted shrink-0" />
                    <span className="flex flex-col">
                      <span className="text-[13px] font-medium text-text">{t.name}</span>
                      {t.display_name && t.display_name !== t.name && (
                        <span className="text-[11px] text-muted">{t.display_name}</span>
                      )}
                    </span>
                  </span>
                </Cell>
                <Cell className="font-mono">{t.default_pool || "default"}</Cell>
                <Cell>
                  {t.quota_bytes ? (
                    <span className="flex items-center gap-2.5">
                      {/* Used is unknown until per-tenant accounting exists, so
                          the track stays empty rather than showing a guess. */}
                      <CapacityBar used={0} total={t.quota_bytes} className="flex-1 min-w-24" />
                      <span className="font-mono text-[11px] text-muted whitespace-nowrap">
                        — / {formatBytes(t.quota_bytes)}
                      </span>
                    </span>
                  ) : (
                    <span className="text-[12px] text-muted">Unlimited</span>
                  )}
                </Cell>
                <Cell align="right" className="font-mono">
                  {bucketsByTenant[t.name] ?? 0}
                </Cell>
                <Cell>
                  {t.oidc_provider ? (
                    <Chip mono>{t.oidc_provider}</Chip>
                  ) : (
                    <span className="text-[11px] text-faint">password</span>
                  )}
                </Cell>
                <Cell align="right" className="font-mono">
                  {t.admin_users?.length ?? 0}
                </Cell>
                <Cell>
                  <Badge kind={t.enabled ? "ok" : "neutral"}>
                    {t.enabled ? "Active" : "Disabled"}
                  </Badge>
                </Cell>
                <Cell align="right">
                  <span className="inline-flex items-center gap-0.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                    <button
                      onClick={() => void openAdmins(t.name)}
                      title="Tenant admins"
                      className="p-1 rounded text-muted hover:text-text hover:bg-surface-2"
                    >
                      <Users size={13} />
                    </button>
                    <button
                      onClick={() => startEdit(t)}
                      title="Edit tenant"
                      className="p-1 rounded text-muted hover:text-text hover:bg-surface-2"
                    >
                      <Settings2 size={13} />
                    </button>
                    <button
                      onClick={() => void remove(t.name)}
                      title="Delete tenant"
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

/// Placeholder for a panel whose series does not exist yet. Names the metric
/// and why it is missing — an empty chart would read as "no traffic", which is
/// a different and wrong statement.
function NeedsSeries({ metric, reason }: { metric: string; reason: string }) {
  return (
    <div className="h-[200px] flex flex-col items-center justify-center text-center px-6 gap-1.5">
      <code className="font-mono text-[11px] text-text-2 bg-surface-2 px-1.5 py-px rounded-[5px]">
        {metric}
      </code>
      <p className="text-[11px] text-muted max-w-sm">{reason}</p>
    </div>
  );
}
