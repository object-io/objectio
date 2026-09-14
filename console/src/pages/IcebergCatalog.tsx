import { useEffect, useState } from "react";
import {
  ArrowLeft,
  ChevronRight,
  FolderOpen,
  Plus,
  Shield,
  Table2,
  Trash2,
  Warehouse,
} from "lucide-react";
import PageHeader from "../components/PageHeader";
import { iceberg } from "../api/client";
import { Badge, Button, Card, Chip, Input, Table, Row, Cell } from "../components/ui";

/// Per-table facts the list view shows. The list endpoint returns names only,
/// so these come from a bounded fan-out of metadata reads — a namespace with
/// hundreds of tables should not turn opening it into hundreds of requests.
interface TableFacts {
  snapshots: number;
  lastUpdatedMs: number;
}
const METADATA_FANOUT = 25;

/// Module scope, not the component body: it reads the clock, and the hooks
/// purity rule rightly objects to that inside a render.
function ago(ms: number): string {
  if (!ms) return "—";
  const mins = Math.round((Date.now() - ms) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs} h ago`;
  return `${Math.round(hrs / 24)} d ago`;
}

interface WarehouseInfo {
  name: string;
  bucket: string;
  location: string;
  tenant: string;
  created_at: number;
}

type View = "warehouses" | "namespaces" | "tables" | "detail";

export default function IcebergCatalog() {
  const [view, setView] = useState<View>("warehouses");

  // Warehouses
  const [warehouses, setWarehouses] = useState<WarehouseInfo[]>([]);
  const [showCreateWh, setShowCreateWh] = useState(false);
  const [newWhName, setNewWhName] = useState("");

  // Namespaces
  const [selectedWh, setSelectedWh] = useState<WarehouseInfo | null>(null);
  const [namespaces, setNamespaces] = useState<string[][]>([]);
  const [showCreateNs, setShowCreateNs] = useState(false);
  const [newNsName, setNewNsName] = useState("");

  // Tables
  const [selectedNs, setSelectedNs] = useState("");
  const [tables, setTables] = useState<{ namespace: string[]; name: string }[]>(
    []
  );

  // Detail
  const [selectedTable, setSelectedTable] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [selectedTableName, setSelectedTableName] = useState("");

  const [nsProps, setNsProps] = useState<Record<string, string>>({});
  const [facts, setFacts] = useState<Record<string, TableFacts>>({});
  const [loading, setLoading] = useState(true);

  // Load warehouses
  // No synchronous `setLoading(true)`: the initial state already covers the
  // mount path, and a refresh updating in place reads better than flashing
  // a spinner over data already on screen.
  const loadWarehouses = () => {
    fetch("/_admin/warehouses")
      .then((r) => r.json())
      .then((d) => setWarehouses(d.warehouses || []))
      .catch(() => setWarehouses([]))
      .finally(() => setLoading(false));
  };

  useEffect(loadWarehouses, []);

  const createWarehouse = async () => {
    if (!newWhName.trim()) return;
    await fetch("/_admin/warehouses", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newWhName }),
    });
    setNewWhName("");
    setShowCreateWh(false);
    loadWarehouses();
  };

  const deleteWarehouse = async (name: string) => {
    if (!confirm(`Delete warehouse "${name}" and its backing bucket?`)) return;
    await fetch(`/_admin/warehouses/${name}`, { method: "DELETE" });
    loadWarehouses();
  };

  // Open warehouse → show namespaces
  const openWarehouse = (wh: WarehouseInfo) => {
    setSelectedWh(wh);
    setView("namespaces");
    setLoading(true);
    iceberg
      .listNamespaces(wh.name)
      .then((r) => setNamespaces(r.namespaces || []))
      .catch(() => setNamespaces([]))
      .finally(() => setLoading(false));
  };

  const whName = selectedWh?.name;

  const createNamespace = async () => {
    if (!newNsName.trim()) return;
    await iceberg.createNamespace([newNsName], {}, whName);
    setNewNsName("");
    setShowCreateNs(false);
    openWarehouse(selectedWh!);
  };

  const deleteNamespace = async (ns: string) => {
    if (!confirm(`Delete namespace "${ns}"?`)) return;
    await iceberg.deleteNamespace(ns, whName);
    openWarehouse(selectedWh!);
  };

  // Open namespace → show tables
  const openNamespace = async (ns: string) => {
    setSelectedNs(ns);
    setView("tables");
    setFacts({});
    iceberg
      .getNamespace(ns, whName)
      .then((r) => setNsProps(r.properties || {}))
      .catch(() => setNsProps({}));
    const r = await iceberg.listTables(ns, whName);
    const ids = r.identifiers || [];
    setTables(ids);
    const got: Record<string, TableFacts> = {};
    await Promise.all(
      ids.slice(0, METADATA_FANOUT).map(async (t) => {
        try {
          const m = (await iceberg.getTable(ns, t.name, whName)) as {
            metadata?: { snapshots?: unknown[]; "last-updated-ms"?: number };
            snapshots?: unknown[];
            "last-updated-ms"?: number;
          };
          // The REST spec nests these under `metadata`; some servers return
          // them flat. Read both rather than showing a blank for one shape.
          const meta = m.metadata ?? m;
          got[t.name] = {
            snapshots: Array.isArray(meta.snapshots) ? meta.snapshots.length : 0,
            lastUpdatedMs: Number(meta["last-updated-ms"] ?? 0),
          };
        } catch {
          /* one unreadable table should not blank the whole column */
        }
      })
    );
    setFacts(got);
  };

  const deleteTable = async (ns: string, name: string) => {
    if (!confirm(`Delete table "${ns}.${name}"?`)) return;
    await iceberg.deleteTable(ns, name, whName);
    openNamespace(ns);
  };

  // Open table detail
  const openTable = async (ns: string, name: string) => {
    setSelectedTableName(`${ns}.${name}`);
    setView("detail");
    try {
      const r = await iceberg.getTable(ns, name, whName);
      // Strip vended credentials from display — they're transient, not metadata
      // Vended credentials are transient, not metadata — drop them from
      // what we display.
      const tableMetadata = { ...r };
      delete (tableMetadata as { config?: unknown }).config;
      setSelectedTable(tableMetadata);
    } catch (e) {
      setSelectedTable({ error: String(e) });
    }
  };

  const goBack = () => {
    if (view === "detail") {
      setView("tables");
      setSelectedTable(null);
    } else if (view === "tables") {
      setView("namespaces");
      setSelectedNs("");
    } else if (view === "namespaces") {
      setView("warehouses");
      setSelectedWh(null);
    }
  };

  // Breadcrumb
  const breadcrumb: { label: string; action?: () => void }[] = [
    { label: "Warehouses", action: () => setView("warehouses") },
  ];
  if (selectedWh) {
    breadcrumb.push({
      label: selectedWh.name,
      action: () => openWarehouse(selectedWh),
    });
  }
  if (selectedNs) {
    breadcrumb.push({
      label: selectedNs,
      action: () => openNamespace(selectedNs),
    });
  }
  if (view === "detail") {
    breadcrumb.push({ label: selectedTableName });
  }

  const policyStatements = (() => {
    const raw = nsProps.__policy;
    if (!raw) return 0;
    try {
      const doc = JSON.parse(raw) as { Statement?: unknown[] };
      return Array.isArray(doc.Statement) ? doc.Statement.length : 0;
    } catch {
      return 0;
    }
  })();

  return (
    <div className="p-6">
      <PageHeader
        title="Tables"
        description="Iceberg REST catalog · warehouses, namespaces, tables"
        action={
          view === "warehouses" ? (
            <Button variant="primary" icon={<Plus size={13} />} onClick={() => setShowCreateWh(true)}>
              Create warehouse
            </Button>
          ) : view === "namespaces" ? (
            <Button variant="primary" icon={<Plus size={13} />} onClick={() => setShowCreateNs(true)}>
              Create namespace
            </Button>
          ) : null
        }
      />

      {view !== "warehouses" && (
        <div className="flex items-center justify-between gap-3 mb-4 flex-wrap">
          <nav className="flex items-center gap-1.5 text-[13px] min-w-0">
            <button onClick={goBack} className="text-faint hover:text-text p-0.5 mr-1" title="Back">
              <ArrowLeft size={14} />
            </button>
            {breadcrumb.map((b, i) => (
              <span key={i} className="flex items-center gap-1.5 min-w-0">
                {i > 0 && <ChevronRight size={12} className="text-faint shrink-0" />}
                {b.action ? (
                  <button onClick={b.action} className="text-accent hover:underline truncate">
                    {b.label}
                  </button>
                ) : (
                  <span className="text-text font-medium truncate">{b.label}</span>
                )}
              </span>
            ))}
          </nav>
          {/* Every Iceberg REST call is scoped by warehouse and the gateway
              rejects a request without it, so the active one is shown rather
              than left implicit. */}
          {selectedWh && <Chip mono>warehouse={selectedWh.name}</Chip>}
        </div>
      )}

      {view === "warehouses" && (
        <>
          {showCreateWh && (
            <Card title="Create warehouse" className="mb-4">
              <div className="flex gap-2 items-end">
                <div className="flex-1">
                  <Input
                    value={newWhName}
                    onChange={(e) => setNewWhName(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && void createWarehouse()}
                    placeholder="warehouse-name"
                    autoFocus
                    hint="Meta provisions a backing bucket named iceberg-<name>."
                  />
                </div>
                <Button variant="primary" onClick={() => void createWarehouse()} disabled={!newWhName.trim()}>
                  Create
                </Button>
                <Button onClick={() => setShowCreateWh(false)}>Cancel</Button>
              </div>
            </Card>
          )}

          <Table
            columns={[
              { key: "wh", label: "Warehouse" },
              { key: "location", label: "Location" },
              { key: "bucket", label: "Bucket", className: "w-56" },
              { key: "actions", label: "", className: "w-16" },
            ]}
            loading={loading}
            empty="No warehouses. Create one to start managing Iceberg tables."
            footer={
              warehouses.length
                ? `${warehouses.length} warehouse${warehouses.length === 1 ? "" : "s"}`
                : undefined
            }
          >
            {warehouses.length
              ? warehouses.map((wh) => (
                  <Row key={wh.name}>
                    <Cell>
                      <button
                        onClick={() => openWarehouse(wh)}
                        className="flex items-center gap-2 text-[13px] font-medium text-text hover:text-accent"
                      >
                        <Warehouse size={14} className="text-muted shrink-0" />
                        {wh.name}
                      </button>
                    </Cell>
                    <Cell className="font-mono text-[11px]">{wh.location}</Cell>
                    <Cell className="font-mono text-[11px]">{wh.bucket}</Cell>
                    <Cell align="right">
                      <button
                        onClick={() => void deleteWarehouse(wh.name)}
                        title="Delete warehouse and its bucket"
                        className="p-1 rounded text-muted hover:text-err hover:bg-surface-2
                          opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <Trash2 size={13} />
                      </button>
                    </Cell>
                  </Row>
                ))
              : undefined}
          </Table>
        </>
      )}

      {view === "namespaces" && (
        <>
          {showCreateNs && (
            <Card title="Create namespace" className="mb-4">
              <div className="flex gap-2 items-end">
                <div className="flex-1">
                  <Input
                    value={newNsName}
                    onChange={(e) => setNewNsName(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && void createNamespace()}
                    placeholder="events"
                    autoFocus
                  />
                </div>
                <Button variant="primary" onClick={() => void createNamespace()} disabled={!newNsName.trim()}>
                  Create
                </Button>
                <Button onClick={() => setShowCreateNs(false)}>Cancel</Button>
              </div>
            </Card>
          )}

          <Table
            columns={[
              { key: "ns", label: "Namespace" },
              { key: "actions", label: "", className: "w-16" },
            ]}
            loading={loading}
            empty="No namespaces"
            footer={
              namespaces.length
                ? `${namespaces.length} namespace${namespaces.length === 1 ? "" : "s"} in ${selectedWh?.name}`
                : undefined
            }
          >
            {namespaces.length
              ? namespaces.map((ns) => {
                  const name = ns.join(".");
                  return (
                    <Row key={name}>
                      <Cell>
                        <button
                          onClick={() => void openNamespace(name)}
                          className="flex items-center gap-2 text-[13px] font-medium text-text hover:text-accent"
                        >
                          <FolderOpen size={14} className="text-muted shrink-0" />
                          {name}
                        </button>
                      </Cell>
                      <Cell align="right">
                        <button
                          onClick={() => void deleteNamespace(name)}
                          title="Delete namespace"
                          className="p-1 rounded text-muted hover:text-err hover:bg-surface-2
                            opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <Trash2 size={13} />
                        </button>
                      </Cell>
                    </Row>
                  );
                })
              : undefined}
          </Table>
        </>
      )}

      {view === "tables" && (
        <>
          <Card title={`Namespace · ${selectedNs}`} className="mb-4">
            <dl className="space-y-1.5 text-[12px]">
              <div className="flex items-baseline justify-between gap-3">
                <dt className="text-muted">Location</dt>
                <dd className="font-mono text-text-2 truncate">
                  {nsProps.location || `${selectedWh?.location ?? ""}/${selectedNs}`}
                </dd>
              </div>
              <div className="flex items-baseline justify-between gap-3">
                <dt className="text-muted">Policy</dt>
                <dd className="text-text-2">
                  {policyStatements
                    ? `namespace policy · ${policyStatements} statement${policyStatements === 1 ? "" : "s"}`
                    : "none — the catalog root policy applies"}
                </dd>
              </div>
            </dl>
          </Card>

          <Table
            columns={[
              { key: "table", label: "Table" },
              { key: "snapshots", label: "Snapshots", align: "right", className: "w-28" },
              { key: "commit", label: "Last commit", align: "right", className: "w-36" },
              { key: "gov", label: "Governance", className: "w-40" },
              { key: "actions", label: "", className: "w-16" },
            ]}
            empty={`No tables in ${selectedNs}`}
            footer={
              tables.length
                ? `${tables.length} table${tables.length === 1 ? "" : "s"} · namespace ${selectedNs}` +
                  (tables.length > METADATA_FANOUT
                    ? ` · snapshots and last commit read for the first ${METADATA_FANOUT}`
                    : "")
                : undefined
            }
          >
            {tables.length
              ? tables.map((t) => {
                  const f = facts[t.name];
                  return (
                    <Row key={t.name}>
                      <Cell>
                        <button
                          onClick={() => void openTable(selectedNs, t.name)}
                          className="flex items-center gap-2 font-mono text-[13px] text-text hover:text-accent"
                        >
                          <Table2 size={14} className="text-muted shrink-0" />
                          {t.name}
                        </button>
                      </Cell>
                      <Cell align="right" className="font-mono">
                        {f ? f.snapshots.toLocaleString() : "—"}
                      </Cell>
                      <Cell align="right">{f ? ago(f.lastUpdatedMs) : "—"}</Cell>
                      <Cell>
                        {policyStatements ? (
                          <Badge kind="info">
                            <Shield size={10} /> namespace policy
                          </Badge>
                        ) : (
                          <span className="text-faint">—</span>
                        )}
                      </Cell>
                      <Cell align="right">
                        <button
                          onClick={() => void deleteTable(selectedNs, t.name)}
                          title="Delete table"
                          className="p-1 rounded text-muted hover:text-err hover:bg-surface-2
                            opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <Trash2 size={13} />
                        </button>
                      </Cell>
                    </Row>
                  );
                })
              : undefined}
          </Table>
        </>
      )}

      {view === "detail" && (
        <Card title={`Table metadata · ${selectedTableName}`} bodyClassName="p-0">
          {selectedTable ? (
            <pre className="p-4 text-[11px] overflow-auto max-h-[calc(100vh-280px)] font-mono text-text-2">
              {JSON.stringify(selectedTable, null, 2)}
            </pre>
          ) : (
            <p className="p-4 text-[12px] text-muted">Loading…</p>
          )}
        </Card>
      )}
    </div>
  );
}
