import { useEffect, useState } from "react";
import {
  Archive,
  Folder,
  File,
  RefreshCw,
  FolderPlus,
  Upload,
} from "lucide-react";
import PageHeader from "../components/PageHeader";

interface S3Object {
  key: string;
  size: number;
  last_modified: number;
  etag: string;
}

interface BucketInfo {
  name: string;
}

function formatSize(bytes: number): string {
  if (bytes === 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export default function Objects() {
  const [buckets, setBuckets] = useState<BucketInfo[]>([]);
  const [selectedBucket, setSelectedBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [objects, setObjects] = useState<S3Object[]>([]);
  const [prefixes, setPrefixes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // `loading`/state already start correct; no synchronous set on mount.
    fetch("/_admin/buckets")
      .then((r) => r.json())
      .then((data) => setBuckets(data.buckets || []))
      .catch(() => setBuckets([]))
      .finally(() => setLoading(false));
  }, []);

  const openBucket = (name: string) => {
    setSelectedBucket(name);
    setPrefix("");
    loadObjects(name, "");
  };
  // No synchronous `setLoading(true)`: the initial state already covers the
  // mount path, and a refresh updating in place reads better than flashing
  // a spinner over data already on screen.

  const loadObjects = (bucket: string, pfx: string) => {
    setPrefix(pfx);
    const params = new URLSearchParams();
    if (pfx) params.set("prefix", pfx);
    params.set("delimiter", "/");
    fetch(`/_admin/buckets/${bucket}/objects?${params}`)
      .then((r) => r.json())
      .then((data) => {
        setObjects(data.contents || []);
        setPrefixes(data.common_prefixes || []);
      })
      .catch(() => {
        setObjects([]);
        setPrefixes([]);
      })
      .finally(() => setLoading(false));
  };

  const navigateUp = () => {
    if (!prefix) {
      setSelectedBucket("");
      setObjects([]);
      setPrefixes([]);
      return;
    }
    const parts = prefix.split("/").filter(Boolean);
    parts.pop();
    const newPrefix = parts.length > 0 ? parts.join("/") + "/" : "";
    loadObjects(selectedBucket, newPrefix);
  };

  // Build breadcrumb segments
  const pathSegments: { label: string; path: string }[] = [];
  if (selectedBucket) {
    pathSegments.push({ label: selectedBucket, path: "" });
    const parts = prefix.split("/").filter(Boolean);
    parts.forEach((part, i) => {
      pathSegments.push({
        label: part,
        path: parts.slice(0, i + 1).join("/") + "/",
      });
    });
  }

  const folderCount = prefixes.length;
  const fileCount = objects.filter((o) => o.key !== prefix).length;

  // Bucket list view
  if (!selectedBucket) {
    return (
      <div className="p-6">
        <PageHeader
          title="Object Browser"
          description="Browse and manage objects in S3 buckets"
        />
        <div className="bg-surface rounded-xl border border-border overflow-hidden">
          <table className="w-full">
            <thead className="bg-surface-2 border-b border-border">
              <tr>
                <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">
                  Bucket
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading ? (
                <tr>
                  <td className="px-4 py-8 text-center">
                    <div className="flex items-center justify-center gap-3">
                      <div className="w-16 h-0.5 bg-border rounded-full overflow-hidden">
                        <div className="h-full w-1/2 bg-accent rounded-full animate-loading-bar" />
                      </div>
                      <span className="text-[12px] text-faint">Loading</span>
                    </div>
                  </td>
                </tr>
              ) : buckets.length === 0 ? (
                <tr>
                  <td className="px-4 py-8 text-center text-[12px] text-faint">
                    No buckets
                  </td>
                </tr>
              ) : (
                buckets.map((b) => (
                  <tr
                    key={b.name}
                    onClick={() => openBucket(b.name)}
                    className="hover:bg-surface-2 cursor-pointer"
                  >
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2.5">
                        <Archive size={14} className="text-orange-500" />
                        <span className="text-[13px] font-medium text-text">
                          {b.name}
                        </span>
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

  // Object browser view
  return (
    <div className="p-6">
      <PageHeader
        title="Object Browser"
        description="Browse and manage objects in S3 buckets"
      />

      <div className="bg-surface rounded-xl border border-border overflow-hidden">
        {/* Breadcrumb bar */}
        <div className="px-4 py-2.5 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-0 text-[13px] text-muted min-w-0">
            {pathSegments.map((seg, i) => (
              <span key={i} className="flex items-center">
                {i > 0 && (
                  <span className="mx-2 text-faint">/</span>
                )}
                <button
                  onClick={() => {
                    if (i === 0) loadObjects(selectedBucket, "");
                    else loadObjects(selectedBucket, seg.path);
                  }}
                  className={`hover:text-text ${
                    i === pathSegments.length - 1
                      ? "text-text font-medium"
                      : "text-muted"
                  }`}
                >
                  {seg.label}
                </button>
              </span>
            ))}
          </div>

          {/* Toolbar icons */}
          <div className="flex items-center gap-1 ml-4">
            <button
              className="p-1.5 text-faint hover:text-text-2 hover:bg-surface-2 rounded"
              title="New folder"
            >
              <FolderPlus size={15} />
            </button>
            <button
              className="p-1.5 text-faint hover:text-text-2 hover:bg-surface-2 rounded"
              title="Upload"
            >
              <Upload size={15} />
            </button>
            <button
              onClick={() => loadObjects(selectedBucket, prefix)}
              className="p-1.5 text-faint hover:text-text-2 hover:bg-surface-2 rounded"
              title="Refresh"
            >
              <RefreshCw size={15} />
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="max-h-[calc(100vh-230px)] overflow-auto">
          {loading ? (
            <div className="flex items-center justify-center gap-3 py-12">
              <div className="w-16 h-0.5 bg-border rounded-full overflow-hidden">
                <div className="h-full w-1/2 bg-accent rounded-full animate-loading-bar" />
              </div>
              <span className="text-[12px] text-faint">Loading</span>
            </div>
          ) : folderCount === 0 && fileCount === 0 && !prefix ? (
            <div className="py-12 text-center">
              <Folder size={28} className="mx-auto mb-2 text-faint" />
              <p className="text-[12px] text-faint">Empty bucket</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-surface-2 border-b border-border sticky top-0">
                <tr>
                  <th className="text-left px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider">
                    Name
                  </th>
                  <th className="text-right px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider w-28">
                    Size
                  </th>
                  <th className="text-right px-4 py-2 text-[11px] font-medium text-muted uppercase tracking-wider w-36">
                    Modified
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {/* Parent folder (..) */}
                {(prefix || selectedBucket) && (
                  <tr
                    onClick={navigateUp}
                    className="hover:bg-surface-2 cursor-pointer"
                  >
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2.5">
                        <Folder
                          size={15}
                          className="text-faint flex-shrink-0"
                        />
                        <span className="text-[13px] text-muted">..</span>
                      </div>
                    </td>
                    <td className="px-4 py-2 text-right text-[12px] text-faint">
                      -
                    </td>
                    <td className="px-4 py-2 text-right text-[12px] text-faint">
                      -
                    </td>
                  </tr>
                )}
                {/* Folders */}
                {prefixes.map((p) => {
                  const name = p.replace(prefix, "").replace(/\/$/, "");
                  return (
                    <tr
                      key={p}
                      className="hover:bg-surface-2 cursor-pointer"
                      onClick={() => loadObjects(selectedBucket, p)}
                    >
                      <td className="px-4 py-2">
                        <div className="flex items-center gap-2.5">
                          <Folder
                            size={15}
                            className="text-yellow-500 flex-shrink-0"
                            fill="currentColor"
                          />
                          <span className="text-[13px] text-text">
                            {name}/
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-2 text-right text-[12px] text-faint">
                        -
                      </td>
                      <td className="px-4 py-2 text-right text-[12px] text-faint">
                        -
                      </td>
                    </tr>
                  );
                })}
                {/* Files */}
                {objects
                  .filter((o) => o.key !== prefix)
                  .map((o) => {
                    const name = o.key.replace(prefix, "");
                    return (
                      <tr key={o.key} className="hover:bg-surface-2">
                        <td className="px-4 py-2">
                          <div className="flex items-center gap-2.5">
                            <File
                              size={15}
                              className="text-faint flex-shrink-0"
                            />
                            <span className="text-[13px] text-text-2 font-mono">
                              {name}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-2 text-right text-[12px] text-muted font-mono">
                          {formatSize(o.size)}
                        </td>
                        <td className="px-4 py-2 text-right text-[12px] text-muted">
                          {o.last_modified
                            ? new Date(
                                o.last_modified * 1000
                              ).toLocaleDateString()
                            : "-"}
                        </td>
                      </tr>
                    );
                  })}
                {/* Empty folder */}
                {folderCount === 0 && fileCount === 0 && prefix && (
                  <tr>
                    <td
                      colSpan={3}
                      className="px-4 py-8 text-center text-[12px] text-faint"
                    >
                      Empty folder
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-1.5 border-t border-border bg-surface-2 text-[11px] text-faint">
          {folderCount} folder{folderCount !== 1 ? "s" : ""}, {fileCount} file
          {fileCount !== 1 ? "s" : ""}
        </div>
      </div>
    </div>
  );
}
