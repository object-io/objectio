import React, { useEffect, useState } from "react";
import {
  Users as UsersIcon,
  Plus,
  Trash2,
  Key,
  Copy,
  Check,
  UserCircle,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import GroupsPanel from "../components/GroupsPanel";

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
        title="Users & Groups"
        description="IAM users, access keys, and groups. Policies attach to either."
        action={
          tab === "users" ? (
            <button
              onClick={() => {
                setShowCreate(true);
                setCredentials(null);
              }}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-fg rounded-lg text-[12px] font-medium hover:bg-primary-hover"
            >
              <Plus size={14} /> Create User
            </button>
          ) : null
        }
      />

      {/* Tab bar */}
      <div className="flex border-b border-border mb-4">
        {(
          [
            { key: "users", label: "Users", icon: UserCircle },
            { key: "groups", label: "Groups", icon: UsersIcon },
          ] as const
        ).map((t) => {
          const Icon = t.icon;
          const active = tab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium border-b-2 -mb-px transition-colors ${
                active
                  ? "border-primary text-text"
                  : "border-transparent text-muted hover:text-text"
              }`}
            >
              <Icon size={13} /> {t.label}
            </button>
          );
        })}
      </div>

      {tab === "groups" && <GroupsPanel />}
      {tab !== "users" && null}
      {tab !== "users" ? null : (
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
    credentials,
    setCredentials,
    copied,
    copyText,
    showCreate,
    setShowCreate,
    newUsername,
    setNewUsername,
    newTenant,
    setNewTenant,
    tenants,
    createUser,
    loading,
    userList,
    loadKeys,
    deleteUser,
    expandedUser,
    keys,
    createKey,
    deleteKey,
    keyFormUser,
    setKeyFormUser,
    keyScope,
    setKeyScope,
    keyReadOnly,
    setKeyReadOnly,
    keyError,
  } = p;
  return (
    <>
      {/* Credentials banner */}
      {credentials && (
        <div className="mb-4 bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <h3 className="text-[12px] font-medium text-yellow-800 mb-2">Save these credentials now — the secret will not be shown again</h3>
          <div className="space-y-1.5 font-mono text-[12px]">
            <div className="flex items-center gap-2">
              <span className="text-muted w-24">Access Key:</span>
              <span className="font-medium">{credentials.access_key_id}</span>
              <button onClick={() => copyText(credentials.access_key_id, "ak")} className="p-0.5">
                {copied === "ak" ? <Check size={12} className="text-green-500" /> : <Copy size={12} className="text-faint" />}
              </button>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted w-24">Secret Key:</span>
              <span className="font-medium">{credentials.secret_access_key}</span>
              <button onClick={() => copyText(credentials.secret_access_key, "sk")} className="p-0.5">
                {copied === "sk" ? <Check size={12} className="text-green-500" /> : <Copy size={12} className="text-faint" />}
              </button>
            </div>
          </div>
          <button onClick={() => setCredentials(null)} className="mt-2 text-[11px] text-yellow-700 underline">Dismiss</button>
        </div>
      )}

      {showCreate && (
        <div className="mb-4 bg-surface rounded-xl border border-border p-4">
          <h3 className="text-[12px] font-medium mb-2">Create New User</h3>
          <div className="flex gap-2">
            <input
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              placeholder="Username"
              className="flex-1 px-2.5 py-1.5 border border-border-strong rounded-lg text-[13px] focus:outline-none focus:ring-1 focus:ring-accent"
              onKeyDown={(e) => e.key === "Enter" && createUser()}
              autoFocus
            />
            <select
              value={newTenant}
              onChange={(e) => setNewTenant(e.target.value)}
              className="px-2.5 py-1.5 border border-border-strong rounded-lg text-[13px] focus:outline-none focus:ring-1 focus:ring-accent"
            >
              <option value="">System (no tenant)</option>
              {tenants.map((t) => (
                <option key={t.name} value={t.name}>{t.name}</option>
              ))}
            </select>
            <button onClick={createUser} className="px-3 py-1.5 bg-primary text-primary-fg rounded-lg text-[12px] font-medium hover:bg-primary-hover">Create</button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 border border-border-strong text-text-2 rounded-lg text-[12px] font-medium hover:bg-surface-2">Cancel</button>
          </div>
        </div>
      )}

      <div className="bg-surface rounded-xl border border-border overflow-hidden">
        <table className="w-full">
          <thead className="bg-surface-2 border-b border-border">
            <tr>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">User</th>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">Tenant</th>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">Status</th>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">Created</th>
              <th className="text-right px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider w-24">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {loading ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center">
                  <div className="flex items-center justify-center gap-3">
                    <div className="w-16 h-0.5 bg-border rounded-full overflow-hidden">
                      <div className="h-full w-1/2 bg-accent rounded-full animate-loading-bar" />
                    </div>
                    <span className="text-[12px] text-faint">Loading</span>
                  </div>
                </td>
              </tr>
            ) : userList.length === 0 ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-[12px] text-faint">No users</td></tr>
            ) : (
              userList.map((u) => (
                <React.Fragment key={u.user_id}>
                <tr className="hover:bg-surface-2 group">
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2">
                        <UsersIcon size={14} className="text-purple-500" />
                        <span className="text-[13px] font-medium">{u.display_name}</span>
                        <span className="text-faint text-[10px] font-mono">{u.user_id.slice(0, 8)}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2 text-[12px]">
                      {u.tenant ? (
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium bg-purple-100 text-purple-800">
                          {u.tenant}
                        </span>
                      ) : (
                        <span className="text-faint">system</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-[12px] text-muted">{u.status}</td>
                    <td className="px-4 py-2 text-[12px] text-muted">{new Date(u.created_at * 1000).toLocaleDateString()}</td>
                    <td className="px-4 py-2 text-right">
                      <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button onClick={() => loadKeys(u.user_id)} className="text-faint hover:text-accent p-1" title="Access Keys">
                          <Key size={14} />
                        </button>
                        <button onClick={() => deleteUser(u.user_id)} className="text-faint hover:text-red-600 p-1">
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                  {expandedUser === u.user_id && (
                    <tr>
                      <td colSpan={5} className="bg-surface-2 px-4 py-3">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-[11px] font-medium text-muted uppercase tracking-wider">Access Keys</h4>
                          <button
                            onClick={() =>
                              setKeyFormUser(keyFormUser === u.user_id ? null : u.user_id)
                            }
                            className="text-[11px] text-accent hover:text-accent flex items-center gap-1"
                          >
                            <Plus size={11} /> New Key
                          </button>
                        </div>

                        {keyFormUser === u.user_id && (
                          <div className="mb-2 bg-surface rounded-lg border border-border p-3 space-y-2">
                            <div>
                              <label className="block text-[11px] font-medium text-muted mb-1">
                                Scope <span className="text-faint">(optional)</span>
                              </label>
                              <input
                                value={keyScope}
                                onChange={(e) => setKeyScope(e.target.value)}
                                placeholder="s3://bucket/prefix/"
                                className="w-full font-mono text-[11px] border border-border rounded-md px-2 py-1.5"
                              />
                              <p className="text-[10px] text-faint mt-1">
                                Confines the key to one bucket or prefix. Leave blank for the
                                user's full access — a scope only narrows, never widens.
                              </p>
                            </div>
                            <label className="flex items-center gap-2 text-[11px] text-text-2">
                              <input
                                type="checkbox"
                                checked={keyReadOnly}
                                onChange={(e) => setKeyReadOnly(e.target.checked)}
                              />
                              Read-only (refuses PUT, POST and DELETE)
                            </label>
                            {keyError && (
                              <p className="text-[11px] text-red-600">{keyError}</p>
                            )}
                            <div className="flex gap-2">
                              <button
                                onClick={() => createKey(u.user_id)}
                                className="text-[11px] bg-accent text-primary-fg rounded-md px-3 py-1.5 hover:bg-accent"
                              >
                                Create Key
                              </button>
                              <button
                                onClick={() => setKeyFormUser(null)}
                                className="text-[11px] text-muted px-2 py-1.5 hover:text-text-2"
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        )}

                        {keys.length === 0 ? (
                          <p className="text-[12px] text-faint">No access keys</p>
                        ) : (
                          <div className="space-y-1.5">
                            {keys.map((k) => (
                              <div key={k.access_key_id} className="flex items-center justify-between bg-surface rounded-lg px-3 py-1.5 border border-border">
                                <div className="flex items-center gap-2 min-w-0">
                                  <span className="font-mono text-[11px]">{k.access_key_id}</span>
                                  {k.scope ? (
                                    <span
                                      className="text-[10px] font-mono bg-amber-50 text-amber-700 border border-amber-200 rounded px-1.5 py-0.5 truncate"
                                      title={`Scoped to ${k.scope}`}
                                    >
                                      {k.scope}
                                    </span>
                                  ) : null}
                                  {k.operation === "READ" ? (
                                    <span className="text-[10px] bg-surface-2 text-text-2 border border-border rounded px-1.5 py-0.5">
                                      read-only
                                    </span>
                                  ) : null}
                                </div>
                                <div className="flex items-center gap-2">
                                  <span className="text-[11px] text-faint">{k.status}</span>
                                  <button onClick={() => deleteKey(k.access_key_id, u.user_id)} className="text-red-400 hover:text-red-600">
                                    <Trash2 size={12} />
                                  </button>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}
