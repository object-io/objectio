import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Archive,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  Eye,
  ExternalLink,
  File,
  Folder,
  FolderPlus,
  MoreHorizontal,
  PanelLeft,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  Upload,
  X,
} from "lucide-react";
import { Badge, Banner, Button, Input } from "../components/ui";

// ---- data shapes ----------------------------------------------------------

interface S3Object {
  key: string;
  size: number;
  last_modified: number;
  etag: string;
  /// Present only once the gateway records who wrote an object.
  writer?: string;
}

interface BucketInfo {
  name: string;
  created_at?: number;
  owner?: string;
  /// 0 = never enabled, 1 = enabled, 2 = suspended.
  versioning?: number;
  pool?: string;
  tenant?: string;
}

interface PoolInfo {
  name: string;
  ec_type?: number;
  ec_k?: number;
  ec_m?: number;
  replication_count?: number;
  failure_domain?: string;
}

interface BucketUsage {
  bucket: string;
  tenant?: string;
  owner?: string;
  created_at?: number;
  objects: number;
  logical_bytes: number;
  stored_bytes: number;
  noncurrent_versions?: number;
  noncurrent_bytes?: number;
  last_modified?: number;
}

/// What a one-byte ranged GET tells us about an object. The console has no
/// HEAD route of its own, and a ranged read returns every header HEAD would
/// without streaming the object.
interface ObjectDetail {
  size?: number;
  contentType?: string;
  etag?: string;
  lastModified?: string;
  encryption?: string;
  kmsKeyId?: string;
  versionId?: string;
  error?: string;
}

// ---- helpers --------------------------------------------------------------

/// Keys go into a wildcard route, so slashes must survive while everything
/// else is escaped — `encodeURIComponent` on the whole key would turn the
/// prefix separators into %2F and address a different object.
function keyPath(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

function objectUrl(bucket: string, key: string): string {
  return `/_admin/buckets/${encodeURIComponent(bucket)}/objects/${keyPath(key)}`;
}

function formatSize(bytes: number | undefined): string {
  if (bytes === undefined || bytes === null || Number.isNaN(bytes)) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const n = bytes / 1024 ** i;
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

/// Timestamps arrive as unix seconds; guard against a millisecond value so a
/// mismatched field shows a sane date instead of one in the year 50000.
function toDate(epoch: number | undefined): Date | null {
  if (!epoch) return null;
  return new Date(epoch > 1e12 ? epoch : epoch * 1000);
}

function formatShort(epoch: number | undefined): string {
  const d = toDate(epoch);
  if (!d) return "—";
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return d.toLocaleString([], {
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDate(epoch: number | undefined): string {
  const d = toDate(epoch);
  if (!d) return "—";
  return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
}

function formatAgo(epoch: number | undefined): string {
  const d = toDate(epoch);
  if (!d) return "—";
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

function versioningLabel(v: number | undefined): { text: string; kind: "ok" | "warn" | "neutral" } {
  if (v === 1) return { text: "Enabled", kind: "ok" };
  if (v === 2) return { text: "Suspended", kind: "warn" };
  return { text: "Off", kind: "neutral" };
}

function protectionLabel(p: PoolInfo | undefined): string | undefined {
  if (!p) return undefined;
  if (p.replication_count && !p.ec_k) return `${p.replication_count}× replica`;
  if (p.ec_k) return `${p.ec_k}+${p.ec_m ?? 0}`;
  return undefined;
}

/// `"abc…-7"` is how S3 marks a multipart upload's ETag — the suffix is the
/// part count.
function multipartParts(etag: string | undefined): number | null {
  const m = etag?.replace(/"/g, "").match(/-(\d+)$/);
  return m ? Number(m[1]) : null;
}

function encryptionLabel(d: ObjectDetail): string {
  if (d.error) return "—";
  if (!d.encryption) return "None";
  if (d.encryption === "AES256") return "SSE-S3 · AES-256";
  if (d.encryption === "aws:kms") return d.kmsKeyId ? `SSE-KMS · ${d.kmsKeyId}` : "SSE-KMS";
  return d.encryption;
}

function copy(text: string) {
  void navigator.clipboard?.writeText(text);
}

// ---- page -----------------------------------------------------------------

export default function Objects() {
  const [params, setParams] = useSearchParams();
  const bucket = params.get("bucket") ?? "";
  const prefix = params.get("prefix") ?? "";

  const [buckets, setBuckets] = useState<BucketInfo[]>([]);
  const [pools, setPools] = useState<PoolInfo[]>([]);
  const [usage, setUsage] = useState<Map<string, BucketUsage> | null>(null);
  const [bucketsLoading, setBucketsLoading] = useState(true);

  const [objects, setObjects] = useState<S3Object[]>([]);
  const [prefixes, setPrefixes] = useState<string[]>([]);
  const [listing, setListing] = useState(false);

  const [bucketFilter, setBucketFilter] = useState("");
  const [search, setSearch] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [menu, setMenu] = useState("");
  const [railOpen, setRailOpen] = useState(false);

  const [selected, setSelected] = useState<S3Object | null>(null);
  const [detail, setDetail] = useState<ObjectDetail | null>(null);

  const fileInput = useRef<HTMLInputElement>(null);

  const go = useCallback(
    (b: string, pfx = "") => {
      const next = new URLSearchParams();
      if (b) next.set("bucket", b);
      if (pfx) next.set("prefix", pfx);
      setParams(next);
      setSelected(null);
      setSearch("");
      setMenu("");
      setRailOpen(false);
    },
    [setParams]
  );

  // Bucket list, pools and usage. Usage is optional: the endpoint may be
  // missing on an older gateway or refused to a tenant console, and the
  // browser must still work without it — the figures just read "—".
  const loadBuckets = useCallback(async () => {
    setBucketsLoading(true);
    const [b, p, u] = await Promise.allSettled([
      fetch("/_admin/buckets").then((r) => (r.ok ? r.json() : Promise.reject(r.status))),
      fetch("/_admin/pools").then((r) => (r.ok ? r.json() : Promise.reject(r.status))),
      fetch("/_admin/usage").then((r) => (r.ok ? r.json() : Promise.reject(r.status))),
    ]);
    setBuckets(b.status === "fulfilled" ? b.value.buckets || [] : []);
    if (p.status === "fulfilled") {
      const v = p.value;
      setPools(Array.isArray(v) ? v : v.pools || []);
    }
    if (u.status === "fulfilled" && Array.isArray(u.value?.buckets)) {
      setUsage(new Map((u.value.buckets as BucketUsage[]).map((x) => [x.bucket, x])));
    } else {
      setUsage(null);
    }
    setBucketsLoading(false);
  }, []);

  useEffect(() => {
    void loadBuckets();
  }, [loadBuckets]);

  const list = useCallback(async (b: string, pfx: string) => {
    if (!b) return;
    setError("");
    setListing(true);
    const qs = new URLSearchParams({ delimiter: "/" });
    if (pfx) qs.set("prefix", pfx);
    try {
      const r = await fetch(`/_admin/buckets/${encodeURIComponent(b)}/objects?${qs}`);
      if (!r.ok) throw new Error(await r.text());
      const d = await r.json();
      setObjects(d.contents || []);
      setPrefixes(d.common_prefixes || []);
    } catch (e) {
      setObjects([]);
      setPrefixes([]);
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setListing(false);
    }
  }, []);

  useEffect(() => {
    void list(bucket, prefix);
  }, [bucket, prefix, list]);

  // Object detail for the drawer.
  useEffect(() => {
    if (!selected || !bucket) return;
    let cancelled = false;
    setDetail(null);
    (async () => {
      try {
        const r = await fetch(objectUrl(bucket, selected.key), {
          headers: { Range: "bytes=0-0" },
        });
        // Drop the body; only the headers are wanted.
        void r.body?.cancel();
        if (!r.ok && r.status !== 416) throw new Error(`${r.status}`);
        const h = r.headers;
        const total = h.get("content-range")?.split("/")[1];
        const d: ObjectDetail = {
          size: total && total !== "*" ? Number(total) : selected.size,
          contentType: h.get("content-type") ?? undefined,
          etag: h.get("etag") ?? selected.etag,
          lastModified: h.get("last-modified") ?? undefined,
          encryption: h.get("x-amz-server-side-encryption") ?? undefined,
          kmsKeyId: h.get("x-amz-server-side-encryption-aws-kms-key-id") ?? undefined,
          versionId: h.get("x-amz-version-id") ?? undefined,
        };
        if (!cancelled) setDetail(d);
      } catch (e) {
        if (!cancelled)
          setDetail({ etag: selected.etag, size: selected.size, error: String(e) });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [selected, bucket]);

  // ---- derived -------------------------------------------------------------

  const current = buckets.find((b) => b.name === bucket);
  const currentUsage = usage?.get(bucket);
  const currentPool = pools.find((p) => p.name === (current?.pool || "default"));

  const railBuckets = useMemo(() => {
    const f = bucketFilter.trim().toLowerCase();
    const rows = buckets.filter((b) => !f || b.name.toLowerCase().includes(f));
    return rows.sort((a, b) => {
      const la = usage?.get(a.name)?.last_modified ?? 0;
      const lb = usage?.get(b.name)?.last_modified ?? 0;
      return lb - la || a.name.localeCompare(b.name);
    });
  }, [buckets, bucketFilter, usage]);

  const q = search.trim().toLowerCase();
  const folders = prefixes
    .filter((p) => p !== prefix)
    .filter((p) => !q || p.slice(prefix.length).toLowerCase().includes(q));
  const files = objects
    .filter((o) => o.key !== prefix)
    .filter((o) => !q || o.key.slice(prefix.length).toLowerCase().includes(q));
  const filesBytes = files.reduce((a, o) => a + (o.size || 0), 0);

  const parts = prefix.split("/").filter(Boolean);
  const up = () => {
    if (!parts.length) {
      go("");
      return;
    }
    const rest = parts.slice(0, -1);
    go(bucket, rest.length ? `${rest.join("/")}/` : "");
  };

  // ---- actions -------------------------------------------------------------

  const refresh = () => {
    void list(bucket, prefix);
    void loadBuckets();
  };

  const upload = async (fl: FileList) => {
    for (const f of Array.from(fl)) {
      setBusy(`Uploading ${f.name}`);
      const r = await fetch(objectUrl(bucket, prefix + f.name), {
        method: "PUT",
        headers: { "Content-Type": f.type || "application/octet-stream" },
        body: f,
      });
      if (!r.ok) {
        setError(`${f.name}: ${await r.text()}`);
        break;
      }
    }
    setBusy("");
    void list(bucket, prefix);
  };

  const newFolder = async () => {
    const name = prompt("Folder name")?.trim().replace(/^\/+|\/+$/g, "");
    if (!name) return;
    setBusy(`Creating ${name}/`);
    // There are no directories in object storage — a folder is a zero-byte
    // key ending in the delimiter, which is what makes an otherwise empty
    // prefix show up in a delimited listing.
    const r = await fetch(objectUrl(bucket, `${prefix}${name}/`), { method: "PUT", body: "" });
    setBusy("");
    if (!r.ok) setError(await r.text());
    void list(bucket, prefix);
  };

  const newBucket = async () => {
    const name = prompt("Bucket name")?.trim();
    if (!name) return;
    setBusy(`Creating bucket ${name}`);
    const r = await fetch("/_admin/buckets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    setBusy("");
    if (!r.ok) {
      setError(await r.text());
      return;
    }
    await loadBuckets();
    go(name);
  };

  const remove = async (key: string) => {
    if (!confirm(`Delete ${key}?`)) return;
    setMenu("");
    setBusy(`Deleting ${key}`);
    const r = await fetch(objectUrl(bucket, key), { method: "DELETE" });
    setBusy("");
    if (!r.ok) setError(await r.text());
    if (selected?.key === key) setSelected(null);
    void list(bucket, prefix);
  };

  // ---- render --------------------------------------------------------------

  const rail = (
    <aside
      className={`w-[260px] shrink-0 border-r border-border bg-surface flex-col
        ${railOpen ? "fixed inset-y-0 left-0 z-40 flex shadow-lg" : "hidden"} lg:static lg:flex lg:shadow-none`}
    >
      <div className="flex items-center justify-between px-4 pt-4 pb-3">
        <span className="font-mono text-[11px] uppercase tracking-wider text-muted">
          Buckets · {buckets.length}
        </span>
        <span className="flex items-center gap-1">
          <Button variant="ghost" size="sm" icon={<Plus size={13} />} onClick={() => void newBucket()}>
            New
          </Button>
          <button
            className="lg:hidden p-1 text-muted hover:text-text"
            onClick={() => setRailOpen(false)}
            title="Close"
          >
            <X size={14} />
          </button>
        </span>
      </div>
      <div className="px-3 pb-2">
        <Input
          icon={<Search size={13} />}
          placeholder="Filter buckets"
          value={bucketFilter}
          onChange={(e) => setBucketFilter(e.target.value)}
        />
      </div>
      <nav className="flex-1 overflow-y-auto px-2 pb-3 space-y-0.5">
        {bucketsLoading && <p className="px-3 py-2 text-[12px] text-faint">Loading…</p>}
        {!bucketsLoading && railBuckets.length === 0 && (
          <p className="px-3 py-2 text-[12px] text-faint">
            {buckets.length ? "No bucket matches" : "No buckets yet"}
          </p>
        )}
        {railBuckets.map((b) => {
          const u = usage?.get(b.name);
          const active = b.name === bucket;
          return (
            <button
              key={b.name}
              onClick={() => go(b.name)}
              className={`w-full flex items-start gap-2.5 px-3 py-2 rounded-[10px] text-left transition-colors ${
                active ? "bg-accent-soft" : "hover:bg-surface-2"
              }`}
            >
              <Archive size={15} className={`mt-0.5 shrink-0 ${active ? "text-accent" : "text-muted"}`} />
              <span className="min-w-0">
                <span
                  className={`block text-[13px] truncate ${active ? "text-accent font-medium" : "text-text"}`}
                >
                  {b.name}
                </span>
                <span className="block text-[11px] text-muted truncate">
                  {u ? `${formatSize(u.logical_bytes)} · ${formatAgo(u.last_modified)}` : "—"}
                </span>
              </span>
            </button>
          );
        })}
        {usage && railBuckets.length > 1 && (
          <p className="px-3 pt-2 text-[11px] text-faint">sorted by last activity</p>
        )}
      </nav>
    </aside>
  );

  const ver = versioningLabel(current?.versioning);
  const stats: { label: string; value: React.ReactNode; sub?: React.ReactNode }[] = [
    {
      label: "Created",
      value: formatDate(current?.created_at ?? currentUsage?.created_at),
      sub: current?.owner || currentUsage?.owner ? `by ${current?.owner || currentUsage?.owner}` : undefined,
    },
    { label: "Last activity", value: formatAgo(currentUsage?.last_modified) },
    {
      label: "Objects",
      value: currentUsage ? currentUsage.objects.toLocaleString() : "—",
    },
    {
      label: "Size",
      value: currentUsage ? formatSize(currentUsage.logical_bytes) : "—",
      sub: currentUsage ? `${formatSize(currentUsage.stored_bytes)} on disk` : undefined,
    },
    {
      label: "Versioning",
      value: <Badge kind={ver.kind}>{ver.text}</Badge>,
      sub:
        currentUsage?.noncurrent_versions !== undefined && current?.versioning
          ? `${currentUsage.noncurrent_versions.toLocaleString()} noncurrent`
          : undefined,
    },
    {
      label: "Pool",
      value: <span className="font-mono">{current?.pool || "default"}</span>,
      sub: [protectionLabel(currentPool), currentPool?.failure_domain && `${currentPool.failure_domain} domain`]
        .filter(Boolean)
        .join(" · ") || undefined,
    },
  ];

  const iconBtn = "p-1 rounded text-muted hover:text-text hover:bg-surface-2";

  const center = (
    <section className="flex-1 min-w-0 overflow-y-auto">
      <div className="px-4 md:px-8 py-6 max-w-[1100px]">
        <div className="flex items-start gap-3 mb-5">
          <button
            className="lg:hidden mt-1 p-1.5 rounded-control border border-border text-muted hover:text-text"
            onClick={() => setRailOpen(true)}
            title="Buckets"
          >
            <PanelLeft size={15} />
          </button>
          <div>
            <h1 className="font-display text-[22px] font-semibold text-text leading-tight">
              Object browser
            </h1>
            <p className="text-[13px] text-muted mt-1">
              Browse, upload and inspect objects across buckets and prefixes
            </p>
          </div>
        </div>

        {busy && (
          <Banner kind="info" className="mb-3">
            {busy}…
          </Banner>
        )}
        {error && (
          <Banner kind="err" className="mb-3" title="That did not go through">
            {error}
          </Banner>
        )}

        {!bucket ? (
          <div className="bg-surface border border-border rounded-card p-10 text-center text-[13px] text-muted">
            {bucketsLoading
              ? "Loading buckets…"
              : buckets.length
                ? "Pick a bucket to browse its objects."
                : "No buckets yet — create one with New."}
          </div>
        ) : (
          <>
            {/* Bucket stats strip */}
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 bg-surface border border-border rounded-card shadow-sm mb-4 overflow-hidden">
              {stats.map((s) => (
                <div key={s.label} className="px-4 py-3 border-border border-b xl:border-b-0 xl:border-r last:border-r-0 min-w-0">
                  <div className="font-mono text-[10px] uppercase tracking-wider text-muted truncate">
                    {s.label}
                  </div>
                  <div className="mt-1 text-[15px] font-semibold text-text tabular-nums truncate">
                    {s.value}
                  </div>
                  <div className="mt-0.5 text-[11px] text-muted truncate">{s.sub ?? " "}</div>
                </div>
              ))}
            </div>

            {/* Breadcrumb */}
            <div className="flex items-center gap-2 mb-3 min-w-0">
              <button
                onClick={up}
                title="Up one level"
                className="shrink-0 h-8 w-8 inline-flex items-center justify-center rounded-control border border-border-strong bg-surface text-text-2 hover:bg-surface-2"
              >
                <ChevronLeft size={15} />
              </button>
              <nav className="flex items-center gap-1 text-[13px] min-w-0 overflow-x-auto whitespace-nowrap">
                <button onClick={() => go("")} className="text-muted hover:text-text px-1">
                  Buckets
                </button>
                <ChevronRight size={13} className="text-faint shrink-0" />
                <button
                  onClick={() => go(bucket)}
                  className="inline-flex items-center gap-1.5 px-1 text-accent hover:underline"
                >
                  <Archive size={13} />
                  {bucket}
                </button>
                {parts.map((p, i) => {
                  const last = i === parts.length - 1;
                  return (
                    <span key={i} className="inline-flex items-center gap-1">
                      <ChevronRight size={13} className="text-faint shrink-0" />
                      {last ? (
                        <span className="font-mono px-2 py-0.5 rounded-control border border-border bg-surface text-text">
                          {p}/
                        </span>
                      ) : (
                        <button
                          onClick={() => go(bucket, `${parts.slice(0, i + 1).join("/")}/`)}
                          className="font-mono px-1 text-text-2 hover:text-text"
                        >
                          {p}
                        </button>
                      )}
                    </span>
                  );
                })}
              </nav>
            </div>

            {/* Toolbar */}
            <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
              <div className="w-full sm:w-[300px]">
                <Input
                  icon={<Search size={13} />}
                  placeholder="Search in prefix"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              <div className="flex items-center gap-2">
                <Button variant="ghost" icon={<RefreshCw size={13} />} onClick={refresh}>
                  Refresh
                </Button>
                <Button icon={<FolderPlus size={13} />} onClick={() => void newFolder()}>
                  New folder
                </Button>
                <Button variant="primary" icon={<Upload size={13} />} onClick={() => fileInput.current?.click()}>
                  Upload
                </Button>
                <input
                  ref={fileInput}
                  type="file"
                  multiple
                  hidden
                  onChange={(e) => {
                    if (e.target.files?.length) void upload(e.target.files);
                    e.target.value = "";
                  }}
                />
              </div>
            </div>

            {/* Listing */}
            <div className="bg-surface border border-border rounded-card shadow-sm overflow-x-auto">
              <table className="w-full border-collapse min-w-[640px]">
                <thead>
                  <tr className="bg-surface-2">
                    {[
                      ["Name", "text-left"],
                      ["Size · Items", "text-right w-36"],
                      ["Modified", "text-right w-40"],
                      ["Writer", "text-left w-36"],
                      ["", "w-28"],
                    ].map(([l, c]) => (
                      <th
                        key={l || "actions"}
                        className={`px-3.5 py-2 font-mono text-[11px] uppercase tracking-wider text-muted font-normal whitespace-nowrap ${c}`}
                      >
                        {l}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {listing && !objects.length && !prefixes.length && (
                    <tr>
                      <td colSpan={5} className="px-3.5 py-8 text-center text-[12px] text-muted">
                        Loading…
                      </td>
                    </tr>
                  )}
                  {prefix && (
                    <tr className="border-t border-border hover:bg-surface-2 cursor-pointer" onClick={up}>
                      <td colSpan={5} className="px-3.5 py-2 h-10 text-[13px] text-muted">
                        <span className="inline-flex items-center gap-2">
                          <ChevronLeft size={14} />
                          <span className="font-mono">..</span>
                        </span>
                      </td>
                    </tr>
                  )}
                  {folders.map((p) => (
                    <tr
                      key={p}
                      className="group border-t border-border hover:bg-surface-2 cursor-pointer"
                      onClick={() => go(bucket, p)}
                    >
                      <td className="px-3.5 py-2 h-10 text-[13px] w-full max-w-0">
                        <span className="flex items-center gap-2 min-w-0 text-text">
                          <Folder size={15} className="text-warn-dot shrink-0" />
                          <span className="font-mono truncate" title={p}>
                            {p.slice(prefix.length)}
                          </span>
                        </span>
                      </td>
                      <td className="px-3.5 text-right text-[12px] text-faint">—</td>
                      <td className="px-3.5 text-right text-[12px] text-faint">—</td>
                      <td className="px-3.5 text-[12px] text-faint">—</td>
                      <td className="px-3.5 text-right" onClick={(e) => e.stopPropagation()}>
                        <span className="inline-flex items-center gap-0.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                          <button title="Open" className={iconBtn} onClick={() => go(bucket, p)}>
                            <Eye size={13} />
                          </button>
                          <button title="Copy s3:// URI" className={iconBtn} onClick={() => copy(`s3://${bucket}/${p}`)}>
                            <Copy size={13} />
                          </button>
                        </span>
                      </td>
                    </tr>
                  ))}
                  {files.map((o) => {
                    const isSel = selected?.key === o.key;
                    return (
                      <tr
                        key={o.key}
                        className={`group border-t border-border cursor-pointer ${
                          isSel ? "bg-accent-soft" : "hover:bg-surface-2"
                        }`}
                        onClick={() => setSelected(o)}
                      >
                        <td className="px-3.5 py-2 h-10 text-[13px] w-full max-w-0">
                          <span className="flex items-center gap-2 min-w-0">
                            <File size={15} className={`shrink-0 ${isSel ? "text-accent" : "text-muted"}`} />
                            <span className="font-mono text-text truncate" title={o.key}>
                              {o.key.slice(prefix.length)}
                            </span>
                          </span>
                        </td>
                        <td className="px-3.5 text-right text-[12px] font-mono text-text-2 whitespace-nowrap">
                          {formatSize(o.size)}
                        </td>
                        <td className="px-3.5 text-right text-[12px] text-text-2 whitespace-nowrap">
                          {formatShort(o.last_modified)}
                        </td>
                        <td className="px-3.5 text-[12px] text-text-2 truncate">
                          {o.writer || <span className="text-faint">—</span>}
                        </td>
                        <td className="px-3.5 text-right" onClick={(e) => e.stopPropagation()}>
                          <span
                            className={`inline-flex items-center gap-0.5 transition-opacity ${
                              isSel || menu === o.key
                                ? "opacity-100"
                                : "opacity-0 group-hover:opacity-100 focus-within:opacity-100"
                            }`}
                          >
                            <button title="Inspect" className={iconBtn} onClick={() => setSelected(o)}>
                              <Eye size={13} />
                            </button>
                            <button
                              title="Copy s3:// URI"
                              className={iconBtn}
                              onClick={() => copy(`s3://${bucket}/${o.key}`)}
                            >
                              <Copy size={13} />
                            </button>
                            <span className="relative">
                              <button
                                title="More"
                                className={iconBtn}
                                onClick={() => setMenu(menu === o.key ? "" : o.key)}
                              >
                                <MoreHorizontal size={13} />
                              </button>
                              {menu === o.key && (
                                <span className="absolute right-0 top-7 z-10 w-40 rounded-card border border-border bg-surface shadow-md py-1 flex flex-col text-left">
                                  <a
                                    href={objectUrl(bucket, o.key)}
                                    onClick={() => setMenu("")}
                                    className="flex items-center gap-2 px-3 py-1.5 text-[12px] text-text-2 hover:bg-surface-2"
                                  >
                                    <Download size={13} /> Download
                                  </a>
                                  <button
                                    onClick={() => {
                                      copy(o.key);
                                      setMenu("");
                                    }}
                                    className="flex items-center gap-2 px-3 py-1.5 text-[12px] text-text-2 hover:bg-surface-2"
                                  >
                                    <Copy size={13} /> Copy key
                                  </button>
                                  <button
                                    onClick={() => void remove(o.key)}
                                    className="flex items-center gap-2 px-3 py-1.5 text-[12px] text-err hover:bg-surface-2"
                                  >
                                    <Trash2 size={13} /> Delete
                                  </button>
                                </span>
                              )}
                            </span>
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                  {!listing && !folders.length && !files.length && (
                    <tr className="border-t border-border">
                      <td colSpan={5} className="px-3.5 py-8 text-center text-[12px] text-muted">
                        {q ? "Nothing in this prefix matches" : prefix ? "Empty prefix" : "Empty bucket"}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
              <div className="px-3.5 py-2.5 border-t border-border text-[11px] text-muted">
                {folders.length} folder{folders.length === 1 ? "" : "s"} · {files.length} object
                {files.length === 1 ? "" : "s"} in prefix · {formatSize(filesBytes)} · delimiter /
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );

  return (
    <div className="flex h-full min-h-screen lg:min-h-0 relative">
      {railOpen && (
        <div className="fixed inset-0 z-30 bg-black/30 lg:hidden" onClick={() => setRailOpen(false)} />
      )}
      {rail}
      {center}
      {selected && bucket && (
        <>
          <div
            className="fixed inset-0 z-30 bg-black/30 xl:hidden"
            onClick={() => setSelected(null)}
          />
          <ObjectDrawer
            bucket={bucket}
            obj={selected}
            detail={detail}
            pool={current?.pool || "default"}
            protection={protectionLabel(currentPool)}
            onClose={() => setSelected(null)}
            onDelete={() => void remove(selected.key)}
          />
        </>
      )}
    </div>
  );
}

// ---- detail drawer --------------------------------------------------------

function ObjectDrawer({
  bucket,
  obj,
  detail,
  pool,
  protection,
  onClose,
  onDelete,
}: {
  bucket: string;
  obj: S3Object;
  detail: ObjectDetail | null;
  pool: string;
  protection?: string;
  onClose: () => void;
  onDelete: () => void;
}) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);

  const name = obj.key.split("/").filter(Boolean).pop() ?? obj.key;
  const size = detail?.size ?? obj.size;
  const etag = detail?.etag ?? obj.etag;
  const partsCount = multipartParts(etag);
  const loading = detail === null;
  const pending = <span className="text-faint">{loading ? "…" : "—"}</span>;

  const fields: [string, React.ReactNode][] = [
    ["Key", <span className="break-all">{obj.key}</span>],
    [
      "Size",
      <>
        {formatSize(size)} · {size.toLocaleString()} B
      </>,
    ],
    ["Content type", detail?.contentType || pending],
    [
      "ETag",
      etag ? (
        <>
          <span className="break-all">{etag.startsWith('"') ? etag : `"${etag}"`}</span>
          {partsCount ? ` · multipart ${partsCount} parts` : ""}
        </>
      ) : (
        pending
      ),
    ],
    [
      "Last modified",
      detail?.lastModified ? new Date(detail.lastModified).toUTCString() : formatShort(obj.last_modified),
    ],
    ["Written by", obj.writer || <span className="text-faint">—</span>],
    ["Storage", `pool ${pool}${protection ? ` · ${protection}` : ""}`],
    ["Encryption", detail ? encryptionLabel(detail) : pending],
    ["Version", detail?.versionId || pending],
  ];

  return (
    <aside className="fixed inset-y-0 right-0 z-40 w-full sm:w-[400px] xl:static xl:z-auto shrink-0 border-l border-border bg-surface flex flex-col shadow-lg xl:shadow-none">
      <div className="flex items-center gap-2 px-5 h-[60px] border-b border-border">
        <File size={16} className="text-muted shrink-0" />
        <span className="flex-1 min-w-0 font-mono text-[14px] font-semibold text-text truncate" title={obj.key}>
          {name}
        </span>
        <button onClick={onClose} title="Close" className="p-1 text-muted hover:text-text">
          <X size={16} />
        </button>
      </div>
      <div className="flex items-center gap-2 px-5 py-3 border-b border-border flex-wrap">
        <a href={objectUrl(bucket, obj.key)}>
          <Button variant="primary" icon={<Download size={13} />}>
            Download
          </Button>
        </a>
        <Button
          icon={<ExternalLink size={13} />}
          disabled
          title="Presigned URLs need an S3 access key and are not issued from the console yet"
        >
          Presign
        </Button>
        <Button variant="ghost" icon={<Copy size={13} />} onClick={() => copy(`s3://${bucket}/${obj.key}`)}>
          Copy URI
        </Button>
      </div>
      <div className="flex-1 overflow-y-auto px-5 py-2">
        {detail?.error && (
          <p className="text-[11px] text-warn py-2">
            Could not read the object's headers ({detail.error}); showing listing data only.
          </p>
        )}
        <dl>
          {fields.map(([k, v]) => (
            <div key={k} className="py-2.5 border-b border-border last:border-b-0">
              <dt className="text-[12px] text-muted">{k}</dt>
              <dd className="mt-1 font-mono text-[12.5px] text-text">{v}</dd>
            </div>
          ))}
        </dl>
      </div>
      <div className="px-5 py-3 border-t border-border">
        <Button variant="secondary" className="text-err" icon={<Trash2 size={13} />} onClick={onDelete}>
          Delete object
        </Button>
      </div>
    </aside>
  );
}
