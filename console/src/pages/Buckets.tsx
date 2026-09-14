import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Database, Plus, Trash2, Settings } from "lucide-react";
import PageHeader from "../components/PageHeader";

interface Bucket {
  name: string;
  created_at?: number;
  owner?: string;
  versioning?: number;
  pool?: string;
  tenant?: string;
}

export default function Buckets() {
  const [bucketList, setBucketList] = useState<Bucket[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [loading, setLoading] = useState(true);

  // No `setLoading(true)` here: `loading` starts true so the mount path is
  // already covered, and a refresh updating the list in place reads better
  // than flashing a spinner over data that is already on screen. Setting it
  // synchronously would also mean a setState inside the mount effect.
  const load = () => {
    fetch("/_admin/buckets")
      .then((r) => r.json())
      .then((data) => setBucketList(data.buckets || []))
      .catch(() => setBucketList([]))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const createBucket = async () => {
    if (!newName.trim()) return;
    await fetch("/_admin/buckets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newName }),
    });
    setNewName("");
    setShowCreate(false);
    load();
  };

  const deleteBucket = async (name: string) => {
    if (!confirm(`Delete bucket "${name}"?`)) return;
    await fetch(`/_admin/buckets/${name}`, { method: "DELETE" });
    load();
  };

  const versioningLabel = (v?: number) => {
    if (v === 1) return "Enabled";
    if (v === 2) return "Suspended";
    return "Off";
  };
  const versioningColor = (v?: number) => {
    if (v === 1) return "bg-green-100 text-green-800";
    if (v === 2) return "bg-yellow-100 text-yellow-800";
    return "bg-surface-2 text-muted";
  };

  return (
    <div className="p-6">
      <PageHeader
        title="Buckets"
        description="Manage S3 buckets"
        action={
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-primary text-primary-fg rounded-lg text-[12px] font-medium hover:bg-primary-hover"
          >
            <Plus size={14} /> Create Bucket
          </button>
        }
      />

      {showCreate && (
        <div className="mb-4 bg-surface rounded-xl border border-border p-4">
          <h3 className="text-[12px] font-medium mb-2">Create New Bucket</h3>
          <div className="flex gap-2">
            <input
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="bucket-name"
              className="flex-1 px-2.5 py-1.5 border border-border-strong rounded-lg text-[13px] focus:outline-none focus:ring-1 focus:ring-accent"
              onKeyDown={(e) => e.key === "Enter" && createBucket()}
              autoFocus
            />
            <button
              onClick={createBucket}
              className="px-3 py-1.5 bg-primary text-primary-fg rounded-lg text-[12px] font-medium hover:bg-primary-hover"
            >
              Create
            </button>
            <button
              onClick={() => setShowCreate(false)}
              className="px-3 py-1.5 border border-border-strong text-text-2 rounded-lg text-[12px] font-medium hover:bg-surface-2"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="bg-surface rounded-xl border border-border overflow-hidden">
        <table className="w-full">
          <thead className="bg-surface-2 border-b border-border">
            <tr>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">Name</th>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">Tenant</th>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">Versioning</th>
              <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">Pool</th>
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
            ) : bucketList.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-[12px] text-faint">
                  No buckets. Create one to get started.
                </td>
              </tr>
            ) : (
              bucketList.map((b) => (
                <tr key={b.name} className="hover:bg-surface-2 group">
                  <td className="px-4 py-2">
                    <Link to={`/buckets/${b.name}`} className="flex items-center gap-2 hover:text-accent">
                      <Database size={14} className="text-accent" />
                      <span className="text-[13px] font-medium">{b.name}</span>
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-[12px] text-muted">
                    {b.tenant ? (
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium bg-purple-100 text-purple-800">
                        {b.tenant}
                      </span>
                    ) : (
                      <span className="text-faint">system</span>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-medium ${versioningColor(b.versioning)}`}>
                      {versioningLabel(b.versioning)}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-[12px] text-muted font-mono">
                    {b.pool || "default"}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <Link
                        to={`/buckets/${b.name}`}
                        className="text-faint hover:text-accent p-1"
                        title="Settings"
                      >
                        <Settings size={14} />
                      </Link>
                      <button
                        onClick={() => deleteBucket(b.name)}
                        className="text-faint hover:text-red-600 p-1"
                        title="Delete"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
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
