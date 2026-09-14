import { useCallback, useEffect, useRef, useState } from "react";
import {
  Archive,
  ChevronLeft,
  Copy,
  Download,
  File,
  Folder,
  FolderPlus,
  MoreHorizontal,
  RefreshCw,
  Trash2,
  Upload,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import { Banner, Button, StatTile, Table, Row, Cell } from "../components/ui";

interface S3Object {
  key: string;
  size: number;
  last_modified: number;
  etag: string;
}

interface BucketInfo {
  name: string;
  versioning?: boolean;
  pool?: string;
  tenant?: string;
}

/// Keys go into a wildcard route, so slashes must survive while everything
/// else is escaped — `encodeURIComponent` on the whole key would turn the
/// prefix separators into %2F and address a different object.
function keyPath(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const n = bytes / 1024 ** i;
  return `${n < 10 && i > 0 ? n.toFixed(1) : Math.round(n)} ${units[i]}`;
}

function formatWhen(epochSeconds: number): string {
  if (!epochSeconds) return "—";
  return new Date(epochSeconds * 1000).toLocaleString([], {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/// Recursive listing is capped so a prefix holding a million keys does not
/// turn opening a folder into a full scan. When the cap is hit the tiles say
/// so rather than reporting the cap as the answer.
const TILE_SCAN_LIMIT = 10_000;

export default function Objects() {
  const [buckets, setBuckets] = useState<BucketInfo[]>([]);
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [objects, setObjects] = useState<S3Object[]>([]);
  const [prefixes, setPrefixes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [menu, setMenu] = useState("");
  const [totals, setTotals] = useState<{ count: number; bytes: number; capped: boolean } | null>(
    null
  );
  const fileInput = useRef<HTMLInputElement>(null);

  const current = buckets.find((b) => b.name === bucket);

  useEffect(() => {
    fetch("/_admin/buckets")
      .then((r) => r.json())
      .then((d) => setBuckets(d.buckets || []))
      .catch(() => setBuckets([]))
      .finally(() => setLoading(false));
  }, []);

  const list = useCallback(async (b: string, pfx: string) => {
    setError("");
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
    }
  }, []);

  /// The two tiles the artboard puts above the table — object count and total
  /// size *under this prefix* — are not in the delimited listing, which by
  /// definition stops at the first slash. They need a second, recursive read.
  const measure = useCallback(async (b: string, pfx: string) => {
    const qs = new URLSearchParams({ "max-keys": String(TILE_SCAN_LIMIT) });
    if (pfx) qs.set("prefix", pfx);
    try {
      const r = await fetch(`/_admin/buckets/${encodeURIComponent(b)}/objects?${qs}`);
      const d = await r.json();
      const raw: S3Object[] = d.contents || [];
      // Folder markers are real zero-byte objects, but counting them here
      // would make "objects in prefix" disagree with what the table shows.
      const rows = raw.filter((o) => !o.key.endsWith("/"));
      setTotals({
        count: rows.length,
        bytes: rows.reduce((a, o) => a + (o.size || 0), 0),
        capped: raw.length >= TILE_SCAN_LIMIT,
      });
    } catch {
      setTotals(null);
    }
  }, []);

  const go = useCallback(
    (b: string, pfx: string) => {
      setBucket(b);
      setPrefix(pfx);
      setMenu("");
      void list(b, pfx);
      void measure(b, pfx);
    },
    [list, measure]
  );

  const upload = async (files: FileList) => {
    for (const f of Array.from(files)) {
      setBusy(`Uploading ${f.name}`);
      const r = await fetch(`/_admin/buckets/${encodeURIComponent(bucket)}/objects/${keyPath(prefix + f.name)}`, {
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
    go(bucket, prefix);
  };

  const newFolder = async () => {
    const name = prompt("Folder name")?.trim().replace(/^\/+|\/+$/g, "");
    if (!name) return;
    setBusy(`Creating ${name}/`);
    // There are no directories in object storage — a folder is a zero-byte
    // key ending in the delimiter, which is what makes an otherwise empty
    // prefix show up in a delimited listing.
    const r = await fetch(
      `/_admin/buckets/${encodeURIComponent(bucket)}/objects/${keyPath(`${prefix}${name}/`)}`,
      { method: "PUT", body: "" }
    );
    setBusy("");
    if (!r.ok) setError(await r.text());
    go(bucket, prefix);
  };

  const remove = async (key: string) => {
    if (!confirm(`Delete ${key}?`)) return;
    setMenu("");
    setBusy(`Deleting ${key}`);
    const r = await fetch(
      `/_admin/buckets/${encodeURIComponent(bucket)}/objects/${keyPath(key)}`,
      { method: "DELETE" }
    );
    setBusy("");
    if (!r.ok) setError(await r.text());
    go(bucket, prefix);
  };

  const copyUri = (key: string) => {
    void navigator.clipboard?.writeText(`s3://${bucket}/${key}`);
    setMenu("");
  };

  // ---- bucket picker -----------------------------------------------------
  if (!bucket) {
    return (
      <div className="p-6">
        <PageHeader
          title="Object browser"
          description="Browse and manage objects by bucket and prefix"
        />
        <Table
          columns={[
            { key: "name", label: "Bucket" },
            { key: "pool", label: "Pool" },
            { key: "versioning", label: "Versioning" },
          ]}
          loading={loading}
          empty="No buckets yet"
          footer={`${buckets.length} bucket${buckets.length === 1 ? "" : "s"}`}
        >
          {buckets.length > 0
            ? buckets.map((b) => (
                <Row key={b.name} className="cursor-pointer">
                  <Cell>
                    <button
                      onClick={() => go(b.name, "")}
                      className="flex items-center gap-2 text-[13px] text-text hover:text-accent"
                    >
                      <Archive size={14} className="text-accent" />
                      {b.name}
                    </button>
                  </Cell>
                  <Cell className="font-mono">{b.pool || "default"}</Cell>
                  <Cell>{b.versioning ? "Enabled" : "Suspended"}</Cell>
                </Row>
              ))
            : undefined}
        </Table>
      </div>
    );
  }

  // ---- browser -----------------------------------------------------------
  const parts = prefix.split("/").filter(Boolean);
  const crumbs = [
    { label: bucket, pfx: "" },
    ...parts.map((p, i) => ({ label: p, pfx: `${parts.slice(0, i + 1).join("/")}/` })),
  ];
  const up = () => {
    const rest = [...parts];
    rest.pop();
    go(bucket, rest.length ? `${rest.join("/")}/` : "");
  };

  const folders = prefixes.filter((p) => p !== prefix);
  const files = objects.filter((o) => o.key !== prefix);

  return (
    <div className="p-6">
      <PageHeader
        title="Object browser"
        description="Browse and manage objects by bucket and prefix"
        action={
          <Button icon={<Archive size={13} />} onClick={() => setBucket("")}>
            Switch bucket
          </Button>
        }
      />

      {/* Breadcrumb + toolbar */}
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <nav className="flex items-center gap-1.5 text-[13px] min-w-0">
          {crumbs.map((c, i) => (
            <span key={c.pfx} className="flex items-center gap-1.5 min-w-0">
              {i > 0 && <span className="text-faint">/</span>}
              <button
                onClick={() => go(bucket, c.pfx)}
                className={`flex items-center gap-1.5 truncate ${
                  i === crumbs.length - 1
                    ? "text-text font-medium"
                    : "text-accent hover:underline"
                }`}
              >
                {i === 0 && <Archive size={13} className="text-muted shrink-0" />}
                {c.label}
                {i > 0 && i === crumbs.length - 1 ? "/" : ""}
              </button>
            </span>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            icon={<RefreshCw size={13} />}
            onClick={() => go(bucket, prefix)}
          >
            Refresh
          </Button>
          <Button icon={<FolderPlus size={13} />} onClick={() => void newFolder()}>
            New folder
          </Button>
          <Button
            variant="primary"
            icon={<Upload size={13} />}
            onClick={() => fileInput.current?.click()}
          >
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

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
        <StatTile
          label="Objects in prefix"
          value={totals ? totals.count.toLocaleString() : "—"}
          sub={totals?.capped ? `first ${TILE_SCAN_LIMIT.toLocaleString()} scanned` : undefined}
        />
        <StatTile
          label="Size"
          value={totals ? formatSize(totals.bytes) : "—"}
          sub={totals?.capped ? "of the scanned keys" : undefined}
        />
        <StatTile
          label="Versioning"
          value={current?.versioning ? "Enabled" : "Suspended"}
        />
        <StatTile label="Pool" value={current?.pool || "default"} />
      </div>

      <Table
        columns={[
          { key: "name", label: "Name" },
          { key: "size", label: "Size", align: "right", className: "w-32" },
          { key: "modified", label: "Modified", align: "right", className: "w-52" },
          { key: "actions", label: "", className: "w-20" },
        ]}
        loading={loading && !objects.length && !prefixes.length}
        empty={prefix ? "Empty prefix" : "Empty bucket"}
        footer={`${folders.length} folder${folders.length === 1 ? "" : "s"} · ${files.length} object${
          files.length === 1 ? "" : "s"
        } · delimiter /`}
      >
        {folders.length || files.length || prefix ? (
          <>
            {prefix && (
              <Row className="cursor-pointer">
                <Cell colSpan={4}>
                  <button
                    onClick={up}
                    className="flex items-center gap-2 text-[13px] text-muted hover:text-text"
                  >
                    <ChevronLeft size={14} />
                    <span className="font-mono">..</span>
                  </button>
                </Cell>
              </Row>
            )}
            {folders.map((p) => (
              <Row key={p}>
                <Cell>
                  <button
                    onClick={() => go(bucket, p)}
                    className="flex items-center gap-2 text-[13px] text-text hover:text-accent"
                  >
                    <Folder size={14} className="text-warn-dot shrink-0" />
                    <span className="font-mono">{p.slice(prefix.length)}</span>
                  </button>
                </Cell>
                <Cell align="right" className="text-faint">
                  —
                </Cell>
                <Cell align="right" className="text-faint">
                  —
                </Cell>
                <Cell />
              </Row>
            ))}
            {files.map((o) => {
              const name = o.key.slice(prefix.length);
              return (
                <Row key={o.key}>
                  <Cell>
                    <span className="flex items-center gap-2">
                      <File size={14} className="text-muted shrink-0" />
                      <span className="font-mono text-text">{name}</span>
                    </span>
                  </Cell>
                  <Cell align="right" className="font-mono">
                    {formatSize(o.size)}
                  </Cell>
                  <Cell align="right">{formatWhen(o.last_modified)}</Cell>
                  <Cell align="right">
                    <span className="inline-flex items-center gap-0.5 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity">
                      <button
                        title="Copy s3:// URI"
                        onClick={() => copyUri(o.key)}
                        className="p-1 rounded text-muted hover:text-text hover:bg-surface-2"
                      >
                        <Copy size={13} />
                      </button>
                      <span className="relative">
                        <button
                          title="More"
                          onClick={() => setMenu(menu === o.key ? "" : o.key)}
                          className="p-1 rounded text-muted hover:text-text hover:bg-surface-2"
                        >
                          <MoreHorizontal size={13} />
                        </button>
                        {menu === o.key && (
                          <span className="absolute right-0 top-7 z-10 w-40 rounded-card border border-border bg-surface shadow-md py-1 flex flex-col text-left">
                            <a
                              href={`/_admin/buckets/${encodeURIComponent(bucket)}/objects/${keyPath(o.key)}`}
                              onClick={() => setMenu("")}
                              className="flex items-center gap-2 px-3 py-1.5 text-[12px] text-text-2 hover:bg-surface-2"
                            >
                              <Download size={13} /> Download
                            </a>
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
                  </Cell>
                </Row>
              );
            })}
          </>
        ) : undefined}
      </Table>
    </div>
  );
}
