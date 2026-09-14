import React, { useEffect, useState } from "react";
import {
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Key,
  Plus,
  Trash2,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import GroupsPanel from "../components/GroupsPanel";
import {
  Badge,
  Banner,
  Button,
  Card,
  Chip,
  Input,
  Select,
  Tabs,
  Table,
  Row,
  Cell,
} from "../components/ui";

interface User {
  user_id: string;
  display_name: string;
  status: string;
  created_at: number;
  tenant: string;
}

interface AccessKey {
  access_key_id: string;
  status: string;
  created_at: number;
  /** "s3://bucket/prefix/" the key is confined to; empty = unscoped. */
  scope?: string;
  /** "READ" or "READ_WRITE". */
  operation?: string;
}

interface Tenant {
  name: string;
}

type Tab = "users" | "groups";

export default function UsersPage() {
  const [tab, setTab] = useState<Tab>("users");
  const [userList, setUserList] = useState<User[]>([]);
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newUsername, setNewUsername] = useState("");
  const [newTenant, setNewTenant] = useState("");
  const [credentials, setCredentials] = useState<{ access_key_id: string; secret_access_key: string } | null>(null);
  const [expandedUser, setExpandedUser] = useState<string | null>(null);
  const [keys, setKeys] = useState<AccessKey[]>([]);
  const [copied, setCopied] = useState("");
  const [loading, setLoading] = useState(true);
  // Scoped-key form. A key can narrow its user's access to one bucket or
  // prefix and/or to reads only; it can never widen it.
  const [keyFormUser, setKeyFormUser] = useState<string | null>(null);
  const [keyScope, setKeyScope] = useState("");
  const [keyReadOnly, setKeyReadOnly] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  // No synchronous `setLoading(true)`: the initial state already covers the
  // mount path, and a refresh updating in place reads better than flashing
  // a spinner over data already on screen.

  const load = () => {
    fetch("/_admin/users")
      .then((r) => r.json())
      .then((d) => setUserList(d.users || []))
      .catch(() => setUserList([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    load();
    fetch("/_admin/tenants")
      .then((r) => r.json())
      .then((d) => {
        const list = Array.isArray(d) ? d : d.tenants || [];
        setTenants(list);
      })
      .catch(() => {});
  }, []);

  const createUser = async () => {
    if (!newUsername.trim()) return;
    // Create user
    const r = await fetch("/_admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ display_name: newUsername, tenant: newTenant }),
    });
    if (!r.ok) return;
    const user = await r.json();

    // Auto-create access key for the new user
    try {
      const kr = await fetch(`/_admin/users/${user.user_id}/access-keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (kr.ok) {
        const keyData = await kr.json();
        setCredentials({
          access_key_id: keyData.access_key_id || keyData.access_key?.access_key_id || "",
          secret_access_key: keyData.secret_access_key || keyData.access_key?.secret_access_key || "",
        });
      } else {
        console.error("Failed to create access key:", kr.status, await kr.text());
      }
    } catch (e) {
      console.error("Error creating access key:", e);
    }

    setNewUsername("");
    setNewTenant("");
    setShowCreate(false);
    load();
  };

  const deleteUser = async (userId: string) => {
    if (!confirm(`Delete user "${userId}"?`)) return;
    await fetch(`/_admin/users/${userId}`, { method: "DELETE" });
    load();
  };

  const loadKeys = async (userId: string) => {
    if (expandedUser === userId) {
      setExpandedUser(null);
      return;
    }
    const r = await fetch(`/_admin/users/${userId}/access-keys`);
    const data = await r.json();
    setKeys(data.access_keys || []);
    setExpandedUser(userId);
  };

  const createKey = async (userId: string) => {
    setKeyError(null);
    const body: { scope?: string; operation?: string } = {};
    if (keyScope.trim()) body.scope = keyScope.trim();
    if (keyReadOnly) body.operation = "r";
    const r = await fetch(`/_admin/users/${userId}/access-keys`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      // The gateway rejects a malformed scope rather than storing one that
      // matches nothing — show its message rather than a generic failure.
      const text = await r.text();
      try {
        setKeyError(JSON.parse(text).error || text);
      } catch {
        setKeyError(text || `Request failed (${r.status})`);
      }
      return;
    }
    const data = await r.json();
    setCredentials(data);
    setKeyFormUser(null);
    setKeyScope("");
    setKeyReadOnly(false);
    if (expandedUser === userId) {
      setExpandedUser(null);
    }
    loadKeys(userId);
  };

  const deleteKey = async (keyId: string, userId: string) => {
    await fetch(`/_admin/access-keys/${keyId}`, { method: "DELETE" });
    loadKeys(userId);
  };

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(""), 2000);
  };

  return (
    <div className="p-6">
      <PageHeader
        title="Users & groups"
        description="IAM users, access keys, and groups. Policies attach to either."
        action={
          tab === "users" ? (
            <Button
              variant="primary"
              icon={<Plus size={13} />}
              onClick={() => {
                setShowCreate(true);
                setCredentials(null);
              }}
            >
              Create user
            </Button>
          ) : null
        }
      />

      <Tabs
        variant="underline"
        value={tab}
        onChange={(k) => setTab(k as Tab)}
        items={[
          { key: "users", label: "Users", count: userList.length },
          { key: "groups", label: "Groups" },
        ]}
        className="mb-4"
      />

      {tab === "groups" ? (
        <GroupsPanel />
      ) : (
        <UsersTabContent
          credentials={credentials}
          setCredentials={setCredentials}
          copied={copied}
          copyText={copyText}
          showCreate={showCreate}
          setShowCreate={setShowCreate}
          newUsername={newUsername}
          setNewUsername={setNewUsername}
          newTenant={newTenant}
          setNewTenant={setNewTenant}
          tenants={tenants}
          createUser={createUser}
          loading={loading}
          userList={userList}
          loadKeys={loadKeys}
          deleteUser={deleteUser}
          expandedUser={expandedUser}
          keys={keys}
          createKey={createKey}
          deleteKey={deleteKey}
          keyFormUser={keyFormUser}
          setKeyFormUser={setKeyFormUser}
          keyScope={keyScope}
          setKeyScope={setKeyScope}
          keyReadOnly={keyReadOnly}
          setKeyReadOnly={setKeyReadOnly}
          keyError={keyError}
        />
      )}
    </div>
  );
}

interface UsersTabProps {
  credentials: { access_key_id: string; secret_access_key: string } | null;
  setCredentials: (
    v: { access_key_id: string; secret_access_key: string } | null,
  ) => void;
  copied: string;
  copyText: (text: string, id: string) => void;
  showCreate: boolean;
  setShowCreate: (v: boolean) => void;
  newUsername: string;
  setNewUsername: (v: string) => void;
  newTenant: string;
  setNewTenant: (v: string) => void;
  tenants: Tenant[];
  createUser: () => void;
  loading: boolean;
  userList: User[];
  loadKeys: (userId: string) => void;
  deleteUser: (userId: string) => void;
  expandedUser: string | null;
  keys: AccessKey[];
  createKey: (userId: string) => void;
  deleteKey: (keyId: string, userId: string) => void;
  keyFormUser: string | null;
  setKeyFormUser: (v: string | null) => void;
  keyScope: string;
  setKeyScope: (v: string) => void;
  keyReadOnly: boolean;
  setKeyReadOnly: (v: boolean) => void;
  keyError: string | null;
}

function UsersTabContent(p: UsersTabProps) {
  const {
    credentials, setCredentials, copied, copyText,
    showCreate, setShowCreate, newUsername, setNewUsername,
    newTenant, setNewTenant, tenants, createUser,
    loading, userList, loadKeys, deleteUser,
    expandedUser, keys, createKey, deleteKey,
    keyFormUser, setKeyFormUser, keyScope, setKeyScope,
    keyReadOnly, setKeyReadOnly, keyError,
  } = p;

  const columns = [
    { key: "user", label: "User" },
    { key: "tenant", label: "Tenant", className: "w-40" },
    { key: "status", label: "Status", className: "w-32" },
    { key: "created", label: "Created", className: "w-36" },
    { key: "keys", label: "Keys", align: "right" as const, className: "w-20" },
    { key: "actions", label: "", className: "w-20" },
  ];

  return (
    <>
      {/* The secret is returned once and never again, so this is the only
          moment it can be copied. It stays until dismissed rather than
          auto-hiding. */}
      {credentials && (
        <Banner
          kind="warn"
          className="mb-4"
          title="Save these credentials now — the secret will not be shown again"
          action={
            <Button size="sm" variant="ghost" onClick={() => setCredentials(null)}>
              Dismiss
            </Button>
          }
        >
          <div className="flex flex-wrap gap-x-8 gap-y-1 mt-1.5">
            {(
              [
                ["AK", credentials.access_key_id, "ak"],
                ["SK", credentials.secret_access_key, "sk"],
              ] as const
            ).map(([label, value, id]) => (
              <span key={id} className="inline-flex items-center gap-1.5 min-w-0">
                <span className="font-mono text-[10px] uppercase tracking-wider opacity-70">
                  {label}
                </span>
                <span className="font-mono text-[12px] truncate">{value}</span>
                <button
                  onClick={() => copyText(value, id)}
                  className="p-0.5 opacity-70 hover:opacity-100"
                  title="Copy"
                >
                  {copied === id ? <Check size={12} /> : <Copy size={12} />}
                </button>
              </span>
            ))}
          </div>
        </Banner>
      )}

      {showCreate && (
        <Card title="Create user" className="mb-4">
          <div className="flex gap-2 items-end flex-wrap">
            <div className="flex-1 min-w-48">
              <Input
                label="Username"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && createUser()}
                placeholder="svc-spark"
                autoFocus
              />
            </div>
            <div className="w-56">
              <Select
                label="Tenant"
                value={newTenant}
                onChange={(e) => setNewTenant(e.target.value)}
              >
                <option value="">System (no tenant)</option>
                {tenants.map((t) => (
                  <option key={t.name} value={t.name}>
                    {t.name}
                  </option>
                ))}
              </Select>
            </div>
            <Button variant="primary" onClick={createUser} disabled={!newUsername.trim()}>
              Create
            </Button>
            <Button onClick={() => setShowCreate(false)}>Cancel</Button>
          </div>
          <p className="mt-2 text-[11px] text-muted">
            An access key is created with the user and shown once.
          </p>
        </Card>
      )}

      <Table
        columns={columns}
        loading={loading}
        empty="No users"
        footer={
          userList.length
            ? `${userList.length} user${userList.length === 1 ? "" : "s"}`
            : undefined
        }
      >
        {userList.length
          ? userList.flatMap((u) => {
              const open = expandedUser === u.user_id;
              const rows: React.ReactElement[] = [
                <Row key={u.user_id}>
                  <Cell>
                    <span className="flex items-center gap-2">
                      <button
                        onClick={() => loadKeys(u.user_id)}
                        className="text-faint hover:text-text"
                        aria-label={open ? "Collapse" : "Expand"}
                      >
                        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                      </button>
                      <span className="text-[13px] font-medium text-text truncate">
                        {u.display_name}
                      </span>
                      <span className="font-mono text-[10px] text-faint">
                        {u.user_id.slice(0, 8)}
                      </span>
                    </span>
                  </Cell>
                  <Cell>
                    {u.tenant ? (
                      <Chip mono>{u.tenant}</Chip>
                    ) : (
                      <span className="text-faint">system</span>
                    )}
                  </Cell>
                  <Cell>
                    <Badge kind={u.status === "Active" ? "ok" : "neutral"}>{u.status}</Badge>
                  </Cell>
                  <Cell>
                    {u.created_at
                      ? new Date(u.created_at * 1000).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })
                      : "—"}
                  </Cell>
                  <Cell align="right" className="font-mono">
                    {open ? keys.length : ""}
                  </Cell>
                  <Cell align="right">
                    <span className="inline-flex items-center gap-0.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                      <button
                        onClick={() => loadKeys(u.user_id)}
                        title="Access keys"
                        className="p-1 rounded text-muted hover:text-text hover:bg-surface-2"
                      >
                        <Key size={13} />
                      </button>
                      <button
                        onClick={() => deleteUser(u.user_id)}
                        title="Delete user"
                        className="p-1 rounded text-muted hover:text-err hover:bg-surface-2"
                      >
                        <Trash2 size={13} />
                      </button>
                    </span>
                  </Cell>
                </Row>,
              ];

              if (!open) return rows;

              rows.push(
                <tr key={`${u.user_id}:keys`} className="border-t border-border bg-surface-2/50">
                  <Cell colSpan={columns.length}>
                    <div className="py-1">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-[10px] uppercase tracking-wider text-muted">
                          Access keys
                        </span>
                        <Button
                          size="sm"
                          icon={<Plus size={12} />}
                          onClick={() =>
                            setKeyFormUser(keyFormUser === u.user_id ? null : u.user_id)
                          }
                        >
                          Create key
                        </Button>
                      </div>

                      {keyFormUser === u.user_id && (
                        <div className="mb-2 bg-surface border border-border rounded-card p-3 space-y-2">
                          <Input
                            label={
                              <>
                                Scope <span className="font-normal text-faint">(optional)</span>
                              </>
                            }
                            value={keyScope}
                            onChange={(e) => setKeyScope(e.target.value)}
                            placeholder="s3://bucket/prefix/"
                            className="font-mono text-[12px]"
                            hint="Confines the key to one bucket or prefix. A scope only narrows the user's access, never widens it."
                          />
                          <label className="flex items-center gap-2 text-[12px] text-text-2">
                            <input
                              type="checkbox"
                              checked={keyReadOnly}
                              onChange={(e) => setKeyReadOnly(e.target.checked)}
                              className="accent-[var(--oio-accent)]"
                            />
                            Read-only — refuses PUT, POST and DELETE
                          </label>
                          {keyError && <Banner kind="err">{keyError}</Banner>}
                          <div className="flex gap-2">
                            <Button size="sm" variant="accent" onClick={() => createKey(u.user_id)}>
                              Create key
                            </Button>
                            <Button size="sm" onClick={() => setKeyFormUser(null)}>
                              Cancel
                            </Button>
                          </div>
                        </div>
                      )}

                      {keys.length === 0 ? (
                        <p className="text-[12px] text-muted">No access keys</p>
                      ) : (
                        <ul className="space-y-1.5">
                          {keys.map((k) => (
                            <li
                              key={k.access_key_id}
                              className="flex items-center gap-2 bg-surface border border-border rounded-control px-3 h-9"
                            >
                              <span className="font-mono text-[12px] text-text">
                                {k.access_key_id}
                              </span>
                              {k.scope && (
                                <Chip mono className="truncate max-w-56">
                                  {k.scope}
                                </Chip>
                              )}
                              {k.operation === "READ" && <Chip>read-only</Chip>}
                              <Badge
                                kind={k.status === "Active" ? "ok" : "neutral"}
                                className="ml-auto"
                              >
                                {k.status}
                              </Badge>
                              <button
                                onClick={() => deleteKey(k.access_key_id, u.user_id)}
                                title="Delete key"
                                className="p-1 rounded text-muted hover:text-err hover:bg-surface-2"
                              >
                                <Trash2 size={12} />
                              </button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </Cell>
                </tr>
              );
              return rows;
            })
          : undefined}
      </Table>
    </>
  );
}
