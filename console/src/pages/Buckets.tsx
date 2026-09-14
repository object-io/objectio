import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Archive, Plus, Search, Settings, Trash2 } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { Badge, Button, Card, Chip, Input, Table, Row, Cell } from "../components/ui";

interface Bucket {
  name: string;
  created_at?: number;
  owner?: string;
  versioning?: number;
  pool?: string;
  tenant?: string;
}

/// Meta stores versioning as an enum, not a bool: 1 = Enabled, 2 = Suspended,
/// anything else = never turned on. Suspended is not Off — existing versions
/// are still kept, only new writes stop creating them.
function versioning(v?: number): { label: string; kind: "ok" | "warn" | "neutral" } {
  if (v === 1) return { label: "Enabled", kind: "ok" };
  if (v === 2) return { label: "Suspended", kind: "warn" };
  return { label: "Off", kind: "neutral" };
}

type Filter = "all" | "versioned" | "suspended";

export default function Buckets() {
  const [bucketList, setBucketList] = useState<Bucket[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [loading, setLoading] = useState(true);

  // No `setLoading(true)` here: `loading` starts true so the mount path is
  // already covered, and a refresh updating the list in place reads better
  // than flashing a spinner over data already on screen.
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
      body: JSON.stringify({ name: newName.trim() }),
    });
    setNewName("");
    setShowCreate(false);
    load();
  };

  const deleteBucket = async (name: string) => {
    if (!confirm(`Delete bucket "${name}"?`)) return;
    await fetch(`/_admin/buckets/${encodeURIComponent(name)}`, { method: "DELETE" });
    load();
  };

  const counts = useMemo(
    () => ({
      all: bucketList.length,
      versioned: bucketList.filter((b) => b.versioning === 1).length,
      suspended: bucketList.filter((b) => b.versioning === 2).length,
    }),
    [bucketList]
  );

  const visible = bucketList
    .filter((b) => (query ? b.name.toLowerCase().includes(query.toLowerCase()) : true))
    .filter((b) =>
      filter === "versioned"
        ? b.versioning === 1
        : filter === "suspended"
          ? b.versioning === 2
          : true
    );

  const FILTERS: Array<[Filter, string, number]> = [
    ["all", "All", counts.all],
    ["versioned", "Versioned", counts.versioned],
    ["suspended", "Suspended", counts.suspended],
  ];

  return (
    <div className="p-6">
      <PageHeader
        title="Buckets"
        description="S3 buckets across all tenants and pools"
        action={
          <Button variant="primary" icon={<Plus size={13} />} onClick={() => setShowCreate(true)}>
            Create bucket
          </Button>
        }
      />

      {showCreate && (
        <Card title="Create bucket" className="mb-4">
          <div className="flex gap-2 items-end">
            <div className="flex-1">
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void createBucket()}
                placeholder="bucket-name"
                autoFocus
                hint="Lowercase letters, digits and dashes; 3–63 characters."
              />
            </div>
            <Button variant="primary" onClick={() => void createBucket()} disabled={!newName.trim()}>
              Create
            </Button>
            <Button onClick={() => setShowCreate(false)}>Cancel</Button>
          </div>
        </Card>
      )}

      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <div className="w-full sm:w-64">
          <Input
            icon={<Search size={13} />}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search buckets"
          />
        </div>
        <div className="inline-flex rounded-control border border-border-strong overflow-hidden">
          {FILTERS.map(([key, label, n]) => (
            <button
              key={key}
              onClick={() => setFilter(key)}
              className={`h-8 px-3 text-[12px] font-medium ${
                filter === key ? "bg-surface-2 text-text" : "bg-surface text-muted hover:text-text"
              }`}
            >
              {label} <span className="text-faint tabular-nums">{n}</span>
            </button>
          ))}
        </div>
        <span className="ml-auto text-[11px] text-muted">
          Showing {visible.length} of {bucketList.length}
        </span>
      </div>

      <Table
        columns={[
          { key: "name", label: "Name" },
          { key: "tenant", label: "Tenant", className: "w-40" },
          { key: "versioning", label: "Versioning", className: "w-36" },
          { key: "pool", label: "Pool", className: "w-36" },
          { key: "size", label: "Size", align: "right", className: "w-28" },
          { key: "actions", label: "", className: "w-20" },
        ]}
        loading={loading}
        empty={bucketList.length === 0 ? "No buckets. Create one to get started." : "No matches"}
        footer={
          bucketList.length
            ? `${visible.length} bucket${visible.length === 1 ? "" : "s"} · size per bucket needs usage accounting, which nothing computes yet`
            : undefined
        }
      >
        {visible.length
          ? visible.map((b) => {
              const v = versioning(b.versioning);
              return (
                <Row key={b.name}>
                  <Cell>
                    <Link
                      to={`/buckets/${encodeURIComponent(b.name)}`}
                      className="flex items-center gap-2 text-[13px] font-medium text-text hover:text-accent"
                    >
                      <Archive size={14} className="text-muted shrink-0" />
                      {b.name}
                    </Link>
                  </Cell>
                  <Cell>
                    {b.tenant ? <Chip mono>{b.tenant}</Chip> : <span className="text-faint">system</span>}
                  </Cell>
                  <Cell>
                    <Badge kind={v.kind}>{v.label}</Badge>
                  </Cell>
                  <Cell className="font-mono">{b.pool || "default"}</Cell>
                  <Cell align="right" className="text-faint">
                    <span title="No per-bucket usage accounting yet">—</span>
                  </Cell>
                  <Cell align="right">
                    <span className="inline-flex items-center gap-0.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                      <Link
                        to={`/buckets/${encodeURIComponent(b.name)}`}
                        title="Bucket settings"
                        className="p-1 rounded text-muted hover:text-text hover:bg-surface-2"
                      >
                        <Settings size={13} />
                      </Link>
                      <button
                        onClick={() => void deleteBucket(b.name)}
                        title="Delete bucket"
                        className="p-1 rounded text-muted hover:text-err hover:bg-surface-2"
                      >
                        <Trash2 size={13} />
                      </button>
                    </span>
                  </Cell>
                </Row>
              );
            })
          : undefined}
      </Table>
    </div>
  );
}
