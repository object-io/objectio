import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Ban,
  Building2,
  ChevronDown,
  ChevronRight,
  Compass,
  Globe2,
  HardDrive,
  Layers3,
  Pause,
  Play,
  Power,
  Server,
  Shuffle,
  X,
} from "lucide-react";
import { Badge, Banner, Button, CapacityBar, Chip } from "../components/ui";
import {
  nodes as nodesApi,
  hostProvider as hostProviderApi,
  drain as drainApi,
  rebalance as rebalanceApi,
  type NodeInfo,
  type OsdAdminState,
  type HostProviderInfo,
  type DrainStatus,
  type RebalanceStatus,
} from "../api/client";

interface HostNode { host: string; osds: string[]; }
interface RackNode { rack: string; hosts: HostNode[]; }
interface DcNode { datacenter: string; racks: RackNode[]; }
interface ZoneNode { zone: string; datacenters: DcNode[]; }
interface RegionNode { region: string; zones: ZoneNode[]; }

interface TopologyData {
  osd_count: number;
  distinct: { region: number; zone: number; datacenter: number; rack: number; host: number };
  tree: RegionNode[];
}

function formatBytes(b: number): string {
  if (!b) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(b) / Math.log(1024)));
  const v = b / 1024 ** i;
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/// Level icons only. The artboard draws every tier on the same surface —
/// depth is carried by indentation and the mono tier label, not by giving
/// each level its own colour, which competed with the status dots.
const LEVEL_ICON = {
  region: Globe2,
  zone: Compass,
  datacenter: Building2,
  rack: Layers3,
  host: Server,
} as const;

type LevelKey = keyof typeof LEVEL_ICON;

function TreeRow({
  level,
  label,
  count,
  right,
  path,
  expanded,
  setExpanded,
  hasChildren,
  children,
  onSelect,
  selected,
}: {
  level: LevelKey;
  label: string;
  count?: string;
  right?: React.ReactNode;
  path: string;
  expanded: Set<string>;
  setExpanded: React.Dispatch<React.SetStateAction<Set<string>>>;
  hasChildren: boolean;
  children?: React.ReactNode;
  onSelect?: () => void;
  selected?: boolean;
}) {
  const open = expanded.has(path);
  const Icon = LEVEL_ICON[level];
  const toggle = () =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });

  return (
    <div>
      <div
        onClick={onSelect}
        className={`flex items-center gap-2 h-9 px-2.5 rounded-control border bg-surface
          ${selected ? "border-accent ring-1 ring-accent-soft bg-accent-soft/40" : "border-border"}
          ${onSelect ? "cursor-pointer hover:border-border-strong" : ""}`}
      >
        {hasChildren ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              toggle();
            }}
            className="text-faint hover:text-text"
            aria-label={open ? "Collapse" : "Expand"}
          >
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </button>
        ) : (
          <span className="w-[13px]" />
        )}
        <Icon size={13} className="text-muted shrink-0" />
        <span className="font-mono text-[10px] uppercase tracking-wider text-faint w-[78px] shrink-0">
          {level}
        </span>
        <span className="font-mono text-[12px] font-medium text-text truncate">
          {label || "(none)"}
        </span>
        {count && <Chip mono>{count}</Chip>}
        {right && <span className="ml-auto flex items-center gap-3 shrink-0">{right}</span>}
      </div>
      {hasChildren && open && (
        <div className="ml-4 pl-4 mt-1.5 space-y-1.5 border-l border-border">{children}</div>
      )}
    </div>
  );
}

interface Props {
  /// Rendered as a tab inside /cluster: the shell already draws the page
  /// header, the host-health summary and Refresh, so this component draws
  /// none of them. Standalone it is the whole page.
  embedded?: boolean;
}

export default function Topology({ embedded = false }: Props = {}) {
  const [topology, setTopology] = useState<TopologyData | null>(null);
  const [osdNodes, setOsdNodes] = useState<NodeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [provider, setProvider] = useState<HostProviderInfo | null>(null);
  const [drains, setDrains] = useState<DrainStatus[]>([]);
  const [rebal, setRebal] = useState<RebalanceStatus | null>(null);
  const [rebalBusy, setRebalBusy] = useState(false);

  useEffect(() => {
    hostProviderApi
      .info()
      .then(setProvider)
      .catch(() =>
        setProvider({ provider: "noop", supports_add_host: false, supports_reboot: false })
      );
  }, []);

  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      drainApi.status().then((d) => !cancelled && setDrains(d.drains ?? [])).catch(() => {});
      rebalanceApi.status().then((r) => !cancelled && setRebal(r)).catch(() => {});
    };
    poll();
    const t = setInterval(poll, 10000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, [refreshKey]);

  // While anything is draining, reload the tree too — the status endpoints
  // above move the shard counter, but the per-host capacity and the
  // auto-finalise from Draining to Out only show up in a fresh node list.
  useEffect(() => {
    if (!osdNodes.some((n) => n.admin_state === "draining")) return;
    const t = setInterval(() => setRefreshKey((k) => k + 1), 15000);
    return () => clearInterval(t);
  }, [osdNodes]);

  const toggleRebalance = useCallback(async () => {
    if (!rebal) return;
    setRebalBusy(true);
    try {
      if (rebal.paused) await rebalanceApi.resume();
      else await rebalanceApi.pause();
      const r = await rebalanceApi.status();
      setRebal(r);
    } catch {
      /* the banner keeps its last known state */
    } finally {
      setRebalBusy(false);
    }
  }, [rebal]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [t, n] = await Promise.all([
          fetch("/_admin/topology").then((r) => r.json()),
          nodesApi.list(),
        ]);
        if (cancelled) return;
        setTopology(t);
        setOsdNodes(n.nodes || []);
        // Auto-expand everything so the tree reads as a diagram on first
        // view. Anything uninteresting can be collapsed.
        const paths = new Set<string>();
        for (const r of (t.tree || []) as RegionNode[]) {
          paths.add(`r:${r.region}`);
          for (const z of r.zones) {
            paths.add(`r:${r.region}/z:${z.zone}`);
            for (const d of z.datacenters) {
              paths.add(`r:${r.region}/z:${z.zone}/d:${d.datacenter}`);
              for (const rk of d.racks) {
                paths.add(`r:${r.region}/z:${z.zone}/d:${d.datacenter}/rk:${rk.rack}`);
              }
            }
          }
        }
        setExpanded(paths);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  // Fast lookup from host name → OSDs on that host. The topology tree
  // identifies hosts by the failure-domain `host` field, which in k8s
  // deployments maps to `spec.nodeName`. Fall back through alternative
  // identifiers to cover bare-metal or legacy registrations.
  //
  // Two independent dedup concerns:
  //
  //  1. The same OSD can match multiple candidate keys (hostname and
  //     node_name are usually identical on k8s pods).
  //  2. Stale registrations: if an OSD pod restarted with fresh state,
  //     meta keeps the old entry until it re-roles the address. Prefer
  //     the online one, then the most recent.
  const osdsByHost = useMemo(() => {
    const m = new Map<string, Map<string, NodeInfo>>();
    for (const osd of osdNodes) {
      const candidates = Array.from(
        new Set([osd.kubernetes_node, osd.hostname, osd.node_name].filter(Boolean) as string[])
      );
      for (const key of candidates) {
        if (!m.has(key)) m.set(key, new Map());
        const byId = m.get(key)!;
        const existing = byId.get(osd.node_id);
        if (!existing || (!existing.online && osd.online)) byId.set(osd.node_id, osd);
      }
    }
    // Collapse to arrays, deduping by address as a last-resort guard
    // against stale same-address ghosts between heartbeats.
    const out = new Map<string, NodeInfo[]>();
    for (const [host, byId] of m) {
      const seenAddr = new Set<string>();
      const list: NodeInfo[] = [];
      for (const osd of byId.values()) {
        if (seenAddr.has(osd.address)) continue;
        seenAddr.add(osd.address);
        list.push(osd);
      }
      out.set(host, list);
    }
    return out;
  }, [osdNodes]);

  const selectedOsds = selectedHost != null ? (osdsByHost.get(selectedHost) ?? []) : [];

  // Topology path to the selected host, walked from the same tree that is
  // drawn on the left so the drawer's breadcrumb cannot disagree with it.
  const selectedPath = useMemo(() => {
    if (!selectedHost || !topology) return null;
    for (const r of topology.tree)
      for (const z of r.zones)
        for (const d of z.datacenters)
          for (const rk of d.racks)
            for (const h of rk.hosts)
              if (h.host === selectedHost)
                return { region: r.region, zone: z.zone, datacenter: d.datacenter, rack: rk.rack };
    return null;
  }, [selectedHost, topology]);

  const hostStats = (host: string) => {
    const osds = osdsByHost.get(host) ?? [];
    const total = osds.reduce((s, o) => s + o.total_capacity, 0);
    const used = osds.reduce((s, o) => s + o.used_capacity, 0);
    const allUp = osds.length > 0 && osds.every((o) => o.online);
    const someUp = osds.some((o) => o.online);
    return {
      osds,
      total,
      used,
      kind: (osds.length === 0 ? "neutral" : allUp ? "ok" : someUp ? "warn" : "err") as
        | "ok"
        | "warn"
        | "err"
        | "neutral",
    };
  };

  const countOsds = {
    rack: (rk: RackNode) => rk.hosts.reduce((n, h) => n + h.osds.length, 0),
    dc: (d: DcNode) => d.racks.reduce((n, rk) => n + countOsds.rack(rk), 0),
    zone: (z: ZoneNode) => z.datacenters.reduce((n, d) => n + countOsds.dc(d), 0),
    region: (r: RegionNode) => r.zones.reduce((n, z) => n + countOsds.zone(z), 0),
  };

  return (
    <div className="flex flex-col lg:flex-row gap-4 items-start">
      <div className="flex-1 min-w-0 w-full">
        {!embedded && (
          <h1 className="text-[15px] font-medium text-text mb-4">Cluster topology</h1>
        )}

        {rebal && <RebalanceBanner status={rebal} busy={rebalBusy} onToggle={toggleRebalance} />}

        <div className="bg-surface border border-border rounded-card shadow-sm">
          <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-border">
            <span className="font-mono text-[11px] uppercase tracking-wider text-muted truncate">
              Topology tree{" "}
              <span className="text-faint">· region › zone › datacenter › rack › host</span>
            </span>
            <Chip mono>CRUSH2</Chip>
          </div>
          <div className="p-4">
            {loading && !topology ? (
              <div className="h-24 flex items-center justify-center text-[12px] text-muted">
                Loading topology…
              </div>
            ) : !topology || topology.tree.length === 0 ? (
              <div className="h-24 flex items-center justify-center text-[12px] text-muted">
                No OSDs registered.
              </div>
            ) : (
              <div className="space-y-1.5 min-w-[640px] lg:min-w-0">
                {topology.tree.map((r) => {
                  const rKey = `r:${r.region}`;
                  return (
                    <TreeRow
                      key={rKey}
                      level="region"
                      label={r.region}
                      count={`${countOsds.region(r)} OSDs`}
                      path={rKey}
                      expanded={expanded}
                      setExpanded={setExpanded}
                      hasChildren
                    >
                      {r.zones.map((z) => {
                        const zKey = `${rKey}/z:${z.zone}`;
                        return (
                          <TreeRow
                            key={zKey}
                            level="zone"
                            label={z.zone}
                            count={`${countOsds.zone(z)} OSDs`}
                            path={zKey}
                            expanded={expanded}
                            setExpanded={setExpanded}
                            hasChildren
                          >
                            {z.datacenters.map((d) => {
                              const dKey = `${zKey}/d:${d.datacenter}`;
                              return (
                                <TreeRow
                                  key={dKey}
                                  level="datacenter"
                                  label={d.datacenter}
                                  count={`${countOsds.dc(d)} OSDs`}
                                  path={dKey}
                                  expanded={expanded}
                                  setExpanded={setExpanded}
                                  hasChildren
                                >
                                  {d.racks.map((rk) => {
                                    const rkKey = `${dKey}/rk:${rk.rack}`;
                                    return (
                                      <TreeRow
                                        key={rkKey}
                                        level="rack"
                                        label={rk.rack}
                                        count={`${countOsds.rack(rk)} OSDs`}
                                        path={rkKey}
                                        expanded={expanded}
                                        setExpanded={setExpanded}
                                        hasChildren
                                      >
                                        {rk.hosts.map((h) => {
                                          const st = hostStats(h.host);
                                          return (
                                            <TreeRow
                                              key={h.host}
                                              level="host"
                                              label={h.host}
                                              count={`${h.osds.length} OSDs`}
                                              path={`${rkKey}/h:${h.host}`}
                                              expanded={expanded}
                                              setExpanded={setExpanded}
                                              hasChildren={false}
                                              onSelect={() => setSelectedHost(h.host)}
                                              selected={selectedHost === h.host}
                                              right={
                                                <>
                                                  <CapacityBar
                                                    used={st.used}
                                                    total={st.total}
                                                    className="w-24 hidden sm:block"
                                                  />
                                                  <span className="font-mono text-[11px] text-muted tabular-nums whitespace-nowrap">
                                                    {formatBytes(st.used)} / {formatBytes(st.total)}
                                                  </span>
                                                  <span
                                                    className={`w-[7px] h-[7px] rounded-full ${
                                                      st.kind === "ok"
                                                        ? "bg-ok"
                                                        : st.kind === "warn"
                                                          ? "bg-warn-dot"
                                                          : st.kind === "err"
                                                            ? "bg-err"
                                                            : "bg-faint"
                                                    }`}
                                                  />
                                                </>
                                              }
                                            />
                                          );
                                        })}
                                      </TreeRow>
                                    );
                                  })}
                                </TreeRow>
                              );
                            })}
                          </TreeRow>
                        );
                      })}
                    </TreeRow>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {selectedHost != null && (
        <HostPanel
          host={selectedHost}
          osds={selectedOsds}
          path={selectedPath}
          provider={provider}
          drains={drains}
          onClose={() => setSelectedHost(null)}
          onChanged={() => setRefreshKey((k) => k + 1)}
        />
      )}
    </div>
  );
}

/// Host detail. In flow at 320px beside the tree rather than an overlay —
/// the artboard keeps the tree readable while a host is open, and an
/// overlay would hide the rack the host sits in, which is the context an
/// operator is usually comparing against.
function HostPanel({
  host,
  osds,
  path,
  provider,
  drains,
  onClose,
  onChanged,
}: {
  host: string;
  osds: NodeInfo[];
  path: { region: string; zone: string; datacenter: string; rack: string } | null;
  provider: HostProviderInfo | null;
  drains: DrainStatus[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState<null | OsdAdminState | "reboot">(null);
  const [error, setError] = useState<string | null>(null);
  // Per-OSD busy state keyed by node_id, so acting on one OSD does not grey
  // out the buttons on its neighbours.
  const [busyOsd, setBusyOsd] = useState<Record<string, OsdAdminState>>({});

  const setOneState = async (nodeId: string, target: OsdAdminState) => {
    setError(null);
    setBusyOsd((b) => ({ ...b, [nodeId]: target }));
    try {
      await nodesApi.setAdminState(nodeId, target);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusyOsd((b) => {
        const next = { ...b };
        delete next[nodeId];
        return next;
      });
    }
  };

  const applyToAll = async (target: OsdAdminState) => {
    setBusy(target);
    setError(null);
    try {
      await Promise.all(osds.map((o) => nodesApi.setAdminState(o.node_id, target)));
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const reboot = async () => {
    setBusy("reboot");
    setError(null);
    try {
      // One OSD pod is enough on k8s — the StatefulSet's other pods stay
      // up. For appliance hosts the provider decides whether to recycle
      // the whole host or a single OSD service.
      const first = osds[0];
      if (!first) return;
      await nodesApi.reboot(first.node_id);
      setTimeout(onChanged, 6000);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const total = osds.reduce((s, o) => s + o.total_capacity, 0);
  const used = osds.reduce((s, o) => s + o.used_capacity, 0);
  const pct = total > 0 ? Math.round((used / total) * 100) : 0;
  const upCount = osds.filter((o) => o.online).length;
  const shards = osds.reduce((s, o) => s + (o.shard_count ?? 0), 0);

  // The tree shows only In OSDs, so a host with 5 In + 4 Out would read as
  // "9" in here without the split. Order by operational priority.
  const inOsds = osds.filter((o) => (o.admin_state ?? "in") === "in");
  const drainingOsds = osds.filter((o) => o.admin_state === "draining");
  const outOsds = osds.filter((o) => o.admin_state === "out");
  const ordered = [...inOsds, ...drainingOsds, ...outOsds];

  // The panel acts on every OSD at once, so show the most restrictive
  // state: an operator needs to see that one OSD is already Out without
  // opening each row.
  const effective: OsdAdminState = outOsds.length
    ? "out"
    : drainingOsds.length
      ? "draining"
      : "in";

  const health =
    osds.length === 0 ? "neutral" : upCount === osds.length ? "ok" : upCount ? "warn" : "err";
  const first = osds[0];

  return (
    <aside className="w-full lg:w-80 shrink-0 bg-surface border border-border rounded-card shadow-sm">
      <div className="flex items-center gap-2 px-3.5 py-2.5 border-b border-border">
        <Server size={14} className="text-muted shrink-0" />
        <span className="font-mono text-[13px] font-semibold text-text truncate">{host}</span>
        <Badge kind={health}>
          {osds.length === 0
            ? "No OSDs"
            : effective === "out"
              ? "Out"
              : effective === "draining"
                ? "Draining"
                : health === "ok"
                  ? "Healthy"
                  : `${upCount}/${osds.length} up`}
        </Badge>
        <button
          onClick={onClose}
          className="ml-auto p-1 rounded text-faint hover:text-text hover:bg-surface-2"
          aria-label="Close"
        >
          <X size={14} />
        </button>
      </div>

      <div className="p-3.5 space-y-3.5">
        <div>
          <p className="font-display text-[26px] leading-none font-semibold text-text tabular-nums">
            {formatBytes(used)}{" "}
            <span className="text-[12px] font-normal text-muted">
              of {formatBytes(total)} · {pct}%
            </span>
          </p>
          <CapacityBar used={used} total={total} className="mt-2" />
        </div>

        <dl className="space-y-1.5 text-[11px]">
          <Field label="Address" value={first?.address} mono />
          <Field label="Kubernetes node" value={first?.kubernetes_node} mono />
          <Field
            label="Path"
            value={
              path
                ? `${path.region} / ${path.zone} / ${path.datacenter} / ${path.rack}`
                : undefined
            }
            mono
          />
          <Field label="Admin state" value={effective} mono />
          <Field label="Shards" value={shards ? shards.toLocaleString() : "0"} />
        </dl>

        {drainingOsds.length > 0 && (
          <DrainProgress drains={drains} ids={drainingOsds.map((o) => o.node_id)} />
        )}

        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-muted mb-1.5">
            OSDs · {upCount} up
          </p>
          <ul className="space-y-2">
            {ordered.map((osd) => {
              const state = osd.admin_state ?? "in";
              const busyFor = busyOsd[osd.node_id];
              // From `in`, "Out" starts a drain — the progress-tracked
              // path that auto-finalises to Out. Flipping straight to Out
              // stranded shards waiting on the background rebalancer.
              const next: OsdAdminState = state === "in" ? "draining" : "in";
              return (
                <li key={osd.node_id}>
                  <div className="flex items-center gap-2">
                    <HardDrive size={12} className="text-faint shrink-0" />
                    <span
                      className={`font-mono text-[12px] truncate ${
                        state === "in" ? "text-text" : "text-muted"
                      }`}
                    >
                      {osd.pod_name || osd.node_name}
                    </span>
                    <Badge kind={osd.online && state === "in" ? "ok" : "neutral"}>
                      {osd.online ? "up" : "down"} / {state}
                    </Badge>
                    <span className="ml-auto font-mono text-[11px] text-muted tabular-nums whitespace-nowrap">
                      {formatBytes(osd.used_capacity)} / {formatBytes(osd.total_capacity)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <CapacityBar
                      used={osd.used_capacity}
                      total={osd.total_capacity}
                      className="flex-1"
                    />
                    <button
                      disabled={busyFor !== undefined || busy !== null}
                      onClick={() => void setOneState(osd.node_id, next)}
                      title={
                        next === "draining"
                          ? "Drain, then auto-finalise Out"
                          : "Return this OSD to placement"
                      }
                      className={`font-mono text-[10px] uppercase tracking-wider px-1.5 rounded-[5px]
                        border disabled:opacity-40 ${
                          next === "in"
                            ? "border-ok/30 text-ok hover:bg-ok-soft"
                            : "border-err/30 text-err hover:bg-err-soft"
                        }`}
                    >
                      {busyFor === next ? "…" : next === "in" ? "in" : "out"}
                    </button>
                  </div>
                </li>
              );
            })}
            {ordered.length === 0 && (
              <li className="text-[11px] text-muted py-1">No OSDs on this host.</li>
            )}
          </ul>
        </div>

        {error && <Banner kind="err">{error}</Banner>}

        <div className="flex flex-wrap gap-2 pt-1 border-t border-border">
          {provider?.supports_reboot && (
            <Button
              size="sm"
              variant="ghost"
              icon={<Power size={12} />}
              disabled={busy !== null || osds.length === 0}
              onClick={() => void reboot()}
              title={`Recycle via ${provider.provider}`}
            >
              {busy === "reboot" ? "Rebooting…" : "Reboot"}
            </Button>
          )}
          {effective === "in" ? (
            <>
              <Button
                size="sm"
                icon={<Shuffle size={12} />}
                disabled={busy !== null || osds.length === 0}
                onClick={() => void applyToAll("draining")}
              >
                {busy === "draining" ? "Draining…" : "Drain host"}
              </Button>
              <Button
                size="sm"
                variant="danger"
                icon={<Ban size={12} />}
                disabled={busy !== null || osds.length === 0}
                onClick={() => void applyToAll("out")}
              >
                {busy === "out" ? "Marking…" : "Mark out"}
              </Button>
            </>
          ) : (
            <Button
              size="sm"
              icon={<Power size={12} />}
              disabled={busy !== null || osds.length === 0}
              onClick={() => void applyToAll("in")}
            >
              {busy === "in" ? "Returning…" : "Mark in"}
            </Button>
          )}
        </div>
      </div>
    </aside>
  );
}

function Field({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-muted shrink-0">{label}</dt>
      <dd className={`text-text-2 truncate text-right ${mono ? "font-mono" : ""}`}>
        {value || "—"}
      </dd>
    </div>
  );
}

/// Cluster-wide rebalancer state. The artboard puts this above the tree
/// because it explains a host sitting at 82% — without it the skew looks
/// like a problem rather than something already being worked on.
function RebalanceBanner({
  status,
  busy,
  onToggle,
}: {
  status: RebalanceStatus;
  busy: boolean;
  onToggle: () => void;
}) {
  // PG counters win when present; the drift fields are the fallback for an
  // older server, where the drift rebalancer is what runs.
  const pgsMoved = status.pgs_moved_total ?? 0;
  const pgCandidates = status.pg_candidates_last_tick ?? 0;
  const pgsScanned = status.pgs_scanned_last_tick ?? 0;
  const active =
    !status.paused &&
    (pgCandidates > 0 ||
      status.drifts_seen_this_pass > 0 ||
      status.scanned_this_pass > 0 ||
      pgsMoved > 0 ||
      status.shards_rebalanced_total > 0);

  return (
    <Banner
      kind={status.paused ? "err" : active ? "warn" : "info"}
      className="mb-4"
      title={`Rebalancer ${status.paused ? "paused" : active ? "running" : "idle"}`}
      action={
        <Button
          size="sm"
          variant="secondary"
          icon={status.paused ? <Play size={12} /> : <Pause size={12} />}
          disabled={busy}
          onClick={onToggle}
        >
          {busy ? "…" : status.paused ? "Resume balancer" : "Pause balancer"}
        </Button>
      }
    >
      {pgsMoved > 0 ? (
        <>
          {pgsMoved.toLocaleString()} PG moves total
          {pgsScanned > 0 && <> · {pgsScanned.toLocaleString()} PGs scanned last tick</>}
          {active && pgCandidates > 0 && (
            <> · {pgCandidates.toLocaleString()} candidates pending</>
          )}
        </>
      ) : (
        <>
          {status.shards_rebalanced_total.toLocaleString()} shards moved total
          {active && status.drifts_seen_this_pass > 0 && (
            <> · {status.drifts_seen_this_pass.toLocaleString()} drifts this pass</>
          )}
        </>
      )}
      {status.last_error && <> · last error: {status.last_error}</>}
    </Banner>
  );
}

/// Drain progress for the Draining OSDs on this host, summed so a
/// multi-OSD host drains as one bar.
function DrainProgress({ drains, ids }: { drains: DrainStatus[]; ids: string[] }) {
  const ours = drains.filter((d) => ids.includes(d.node_id));
  const initial = ours.reduce((s, d) => s + d.initial_shards, 0);
  const remaining = ours.reduce((s, d) => s + d.shards_remaining, 0);
  const migrated = ours.reduce((s, d) => s + d.shards_migrated, 0);
  const pct = initial > 0 ? Math.min(100, Math.round(((initial - remaining) / initial) * 100)) : 0;
  const lastError = ours.find((d) => d.last_error)?.last_error ?? "";

  return (
    <div className="rounded-card border border-warn/25 bg-warn-soft px-2.5 py-2">
      <div className="flex items-center justify-between text-[11px] text-warn">
        <span className="font-medium">Draining</span>
        <span className="tabular-nums">{remaining.toLocaleString()} shards remaining</span>
      </div>
      {initial > 0 && (
        <>
          <div className="mt-1.5 h-1.5 rounded-full bg-surface-2 overflow-hidden">
            <div className="h-full rounded-full bg-warn-dot" style={{ width: `${pct}%` }} />
          </div>
          <p className="mt-1 text-[10px] text-warn tabular-nums">
            {migrated.toLocaleString()} of {initial.toLocaleString()} migrated · {pct}%
          </p>
        </>
      )}
      {lastError && <p className="mt-1 text-[10px] text-err truncate">{lastError}</p>}
      <p className="mt-1.5 text-[10px] text-warn/80">
        The meta leader migrates one shard per OSD every 30s; at zero the OSD
        finalises to Out on its own.
      </p>
    </div>
  );
}
