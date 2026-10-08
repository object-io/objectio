import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  RefreshCw,
  Layers,
  GitBranch,
  HardDrive,
  AlertTriangle,
  ShieldCheck,
  ScanSearch,
} from "lucide-react";
import {
  placementGroups,
  nodes as nodesApi,
  type PlacementGroup,
  type NodeInfo,
  request,
} from "../api/client";

interface Pool {
  name: string;
  ec_type: number;
  ec_k: number;
  ec_m: number;
  ec_local_parity: number;
  ec_global_parity: number;
  replication_count: number;
  failure_domain: string;
  pg_count?: number;
  tier?: string;
}

function ecString(p: Pool): string {
  if (p.ec_type === 2) return `${p.replication_count}× Replication`;
  if (p.ec_type === 1)
    return `LRC ${p.ec_k}+${p.ec_local_parity}+${p.ec_global_parity}`;
  return `${p.ec_k}+${p.ec_m} Reed-Solomon`;
}

function copyCount(p: Pool): number {
  if (p.ec_type === 2) return p.replication_count || 0;
  if (p.ec_type === 1) return p.ec_k + p.ec_local_parity + p.ec_global_parity;
  return p.ec_k + p.ec_m;
}

/** States most severe first, as peering and recovery name them (B31). */
const STATES = [
  "Down",
  "Incomplete",
  "Undersized",
  "WaitTooFull",
  "Degraded",
  "Recovering",
  "Backfilling",
  "Clean",
  "Unknown",
];

/** A state's tone: what needs attention, what is being worked, what's fine. */
function stateTone(state: string): string {
  switch (state) {
    case "Down":
    case "Incomplete":
      return "bg-err-soft text-err border-err/30";
    case "Undersized":
    case "WaitTooFull":
    case "Degraded":
      return "bg-warn-soft text-warn border-warn/30";
    case "Recovering":
    case "Backfilling":
      return "bg-accent-soft text-accent border-accent/30";
    case "Clean":
      return "bg-ok-soft text-ok border-ok/30";
    default:
      return "bg-surface-2 text-muted border-border";
  }
}

function stateOf(pg: PlacementGroup): string {
  return pg.state?.state ?? "Unknown";
}

function ago(unixSecs: number): string {
  if (!unixSecs) return "never";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSecs));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

/// `/cluster/pools/:name` — a pool's placement groups: their health (the
/// state peering last found, recovery's progress, the last scrub), each
/// one's detail, and placement: a per-OSD load bar chart and a PG × OSD
/// matrix (scrollable, so it scales to thousands of PGs).
export default function PoolPlacement() {
  const { name: poolName } = useParams<{ name: string }>();
  const nav = useNavigate();
  const [pool, setPool] = useState<Pool | null>(null);
  const [pgs, setPgs] = useState<PlacementGroup[]>([]);
  const [osds, setOsds] = useState<NodeInfo[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedOsd, setSelectedOsd] = useState<string | null>(null);
  const [selectedPg, setSelectedPg] = useState<number | null>(null);
  const [stateFilter, setStateFilter] = useState<string | null>(null);
  const [scrubNote, setScrubNote] = useState<string | null>(null);

  const load = async () => {
    if (!poolName) return;
    setLoading(true);
    setErr(null);
    try {
      const [p, nodesResp] = await Promise.all([
        request<Pool>("GET", `/_admin/pools/${encodeURIComponent(poolName)}`),
        nodesApi.list(),
      ]);
      // Every page of the pool's PGs.
      const all: PlacementGroup[] = [];
      let start = 0;
      for (;;) {
        const page = await placementGroups.list(poolName, {
          start_at: start,
          max: 10000,
        });
        all.push(...page.pgs);
        if (!page.next_pg_id) break;
        start = page.next_pg_id;
      }
      setPool(p);
      setPgs(all);
      setOsds(nodesResp.nodes);
    } catch (e) {
      setErr(String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [poolName]);

  const osdName = useMemo(() => {
    const m = new Map<string, string>();
    for (const o of osds) m.set(o.node_id, o.node_name || o.node_id.slice(0, 8));
    return m;
  }, [osds]);

  // Per-OSD PG-membership count (acting) — the number the balancer
  // reasons about. Distinct from the shard count (which reflects
  // objects that have been written to PGs that happen to include
  // this OSD).
  const osdPgCount = useMemo(() => {
    const c = new Map<string, number>();
    for (const pg of pgs) {
      for (const osd of pg.acting) {
        c.set(osd, (c.get(osd) ?? 0) + 1);
      }
    }
    return c;
  }, [pgs]);

  const osdEntries = useMemo(() => {
    // Sort by cluster position so the matrix columns stay stable.
    const entries = osds.map((o) => ({
      id: o.node_id,
      name: o.node_name || o.node_id.slice(0, 8),
      pgs: osdPgCount.get(o.node_id) ?? 0,
      shards: o.shard_count ?? 0,
      online: o.online,
      admin_state: o.admin_state,
    }));
    entries.sort((a, b) => a.name.localeCompare(b.name));
    return entries;
  }, [osds, osdPgCount]);

  const byState = useMemo(() => {
    const c = new Map<string, number>();
    for (const pg of pgs) c.set(stateOf(pg), (c.get(stateOf(pg)) ?? 0) + 1);
    return c;
  }, [pgs]);

  const cc = pool ? copyCount(pool) : 0;
  const pgCount = pgs.length;
  const totalSlots = pgCount * cc;
  const target = osdEntries.length > 0 ? totalSlots / osdEntries.length : 0;
  const overloadThresh = target * 1.2;
  const underloadThresh = target * 0.7;

  const maxPg = osdEntries.reduce((m, o) => Math.max(m, o.pgs), 0);

  // Index osd ids into column positions for the matrix.
  const osdIndex = useMemo(() => {
    const m = new Map<string, number>();
    osdEntries.forEach((o, i) => m.set(o.id, i));
    return m;
  }, [osdEntries]);

  /** Up members a PG is moving to: in `up`, not yet in `acting`. */
  const movingTo = (pg: PlacementGroup) =>
    pg.up.filter((u) => u && !pg.acting.includes(u));

  const movingCount = pgs.filter(
    (pg) => movingTo(pg).length > 0 || pg.filling.length > 0,
  ).length;
  const notClean = pgs.filter((pg) => stateOf(pg) !== "Clean").length;

  const listed = pgs
    .filter((pg) => !stateFilter || stateOf(pg) === stateFilter)
    .sort(
      (a, b) =>
        STATES.indexOf(stateOf(a)) - STATES.indexOf(stateOf(b)) ||
        a.pg_id - b.pg_id,
    );

  const detail =
    selectedPg !== null ? pgs.find((p) => p.pg_id === selectedPg) : undefined;

  const scrubNow = async (pg: PlacementGroup) => {
    if (!poolName) return;
    setScrubNote(null);
    try {
      await placementGroups.scrub(poolName, pg.pg_id);
      setScrubNote(`PG ${pg.pg_id}: scrub requested`);
      const fresh = await placementGroups.get(poolName, pg.pg_id);
      setPgs((all) => all.map((p) => (p.pg_id === fresh.pg_id ? fresh : p)));
    } catch (e) {
      setScrubNote(`PG ${pg.pg_id}: ${String(e)}`);
    }
  };

  return (
    <div className="p-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-3">
          <button
            onClick={() => nav("/cluster/pools")}
            className="flex items-center gap-1 text-[12px] text-text-2 hover:text-text"
          >
            <ArrowLeft size={14} />
            Pools
          </button>
          <div className="text-faint">/</div>
          <h1 className="font-display text-[20px] leading-tight font-semibold text-text">{poolName}</h1>
          {pool && (
            <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-surface-2 text-text-2">
              {ecString(pool)}
            </span>
          )}
          {notClean > 0 && (
            <span className="flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-warn-soft text-warn border border-warn/25">
              <AlertTriangle size={11} />
              {notClean} not clean
            </span>
          )}
          {movingCount > 0 && (
            <span className="flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-accent-soft text-accent border border-accent/25">
              {movingCount} moving
            </span>
          )}
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-1.5 px-2.5 py-1 border border-border rounded-lg text-[11px] font-medium text-text-2 hover:bg-surface-2 disabled:opacity-50"
        >
          <RefreshCw size={12} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {err && (
        <div className="mb-3 rounded-lg border border-err/25 bg-err-soft px-3 py-2 text-[12px] text-err">
          {err}
        </div>
      )}

      {/* Summary stats */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <StatCard
          label="Placement groups"
          value={pgCount.toLocaleString()}
          icon={<Layers size={14} />}
          hint={pool?.pg_count && pool.pg_count !== pgCount
            ? `declared ${pool.pg_count}`
            : undefined}
        />
        <StatCard
          label="Clean"
          value={`${(byState.get("Clean") ?? 0).toLocaleString()} / ${pgCount.toLocaleString()}`}
          icon={<ShieldCheck size={14} />}
          hint={notClean > 0 ? `${notClean} need attention or are recovering` : "every PG clean"}
        />
        <StatCard
          label="Shards per PG (k+m)"
          value={cc.toString()}
          icon={<GitBranch size={14} />}
          hint={pool?.failure_domain ? `fd=${pool.failure_domain}` : undefined}
        />
        <StatCard
          label="Target PGs/OSD"
          value={target.toFixed(1)}
          icon={<HardDrive size={14} />}
          hint={`overload ≥ ${overloadThresh.toFixed(1)}, underload ≤ ${underloadThresh.toFixed(1)}`}
        />
      </div>

      {/* Health: PGs by state, the list, one PG's detail */}
      <div className="bg-surface rounded-lg border border-border overflow-hidden mb-4">
        <div className="px-3 py-2 border-b border-border flex items-center justify-between gap-2 flex-wrap">
          <h2 className="text-[12px] font-medium text-text-2 uppercase tracking-wide">
            Placement group health
          </h2>
          <div className="flex items-center gap-1.5 flex-wrap">
            <button
              onClick={() => setStateFilter(null)}
              className={`text-[11px] px-1.5 py-0.5 rounded border ${
                stateFilter === null
                  ? "bg-accent-soft text-accent border-accent/30"
                  : "bg-surface-2 text-text-2 border-border"
              }`}
            >
              All {pgCount}
            </button>
            {STATES.filter((s) => byState.has(s)).map((s) => (
              <button
                key={s}
                onClick={() => setStateFilter(stateFilter === s ? null : s)}
                className={`text-[11px] px-1.5 py-0.5 rounded border ${stateTone(s)} ${
                  stateFilter === s ? "ring-1 ring-current" : ""
                }`}
              >
                {s} {byState.get(s)}
              </button>
            ))}
          </div>
        </div>
        <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="overflow-auto border-r border-border" style={{ maxHeight: "360px" }}>
            <table className="w-full text-[11px]">
              <thead className="sticky top-0 bg-surface z-10 text-muted">
                <tr className="border-b border-border">
                  <th className="px-2 py-1 text-left font-normal">PG</th>
                  <th className="px-2 py-1 text-left font-normal">State</th>
                  <th className="px-2 py-1 text-right font-normal">Objects</th>
                  <th className="px-2 py-1 text-right font-normal">Degraded</th>
                  <th className="px-2 py-1 text-right font-normal">Unfound</th>
                  <th className="px-2 py-1 text-right font-normal">Left</th>
                  <th className="px-2 py-1 text-right font-normal">Scrubbed</th>
                </tr>
              </thead>
              <tbody>
                {listed.map((pg) => {
                  const st = pg.state;
                  return (
                    <tr
                      key={pg.pg_id}
                      onClick={() =>
                        setSelectedPg(selectedPg === pg.pg_id ? null : pg.pg_id)
                      }
                      className={`cursor-pointer hover:bg-surface-2 ${
                        selectedPg === pg.pg_id ? "bg-accent-soft" : ""
                      }`}
                    >
                      <td className="px-2 py-0.5 font-mono text-text-2">{pg.pg_id}</td>
                      <td className="px-2 py-0.5">
                        <span className={`px-1 py-px rounded border text-[10px] ${stateTone(stateOf(pg))}`}>
                          {stateOf(pg)}
                        </span>
                      </td>
                      <td className="px-2 py-0.5 text-right font-mono">{st?.objects ?? "–"}</td>
                      <td className={`px-2 py-0.5 text-right font-mono ${st?.objects_degraded ? "text-warn" : ""}`}>
                        {st?.objects_degraded ?? "–"}
                      </td>
                      <td className={`px-2 py-0.5 text-right font-mono ${st?.objects_unfound ? "text-err font-semibold" : ""}`}>
                        {st?.objects_unfound ?? "–"}
                      </td>
                      <td className="px-2 py-0.5 text-right font-mono">
                        {st?.recovery.remaining ? st.recovery.remaining : "–"}
                      </td>
                      <td className="px-2 py-0.5 text-right text-faint">
                        {pg.scrub?.running ? "running" : ago(pg.scrub?.last_complete ?? 0)}
                      </td>
                    </tr>
                  );
                })}
                {listed.length === 0 && !loading && (
                  <tr>
                    <td colSpan={7} className="px-3 py-6 text-center text-faint">
                      No placement groups{stateFilter ? ` in state ${stateFilter}` : ""}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="p-3 text-[11px] overflow-auto" style={{ maxHeight: "360px" }}>
            {detail ? (
              <PgDetail
                pg={detail}
                osdName={osdName}
                onScrub={() => scrubNow(detail)}
                note={scrubNote}
              />
            ) : (
              <div className="text-faint py-6 text-center">
                Select a placement group to see its members, recovery and scrub.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Per-OSD bar chart */}
      <div className="bg-surface rounded-lg border border-border overflow-hidden mb-4">
        <div className="px-3 py-2 border-b border-border flex items-center justify-between">
          <h2 className="text-[12px] font-medium text-text-2 uppercase tracking-wide">
            PG-membership per OSD
          </h2>
          <div className="flex items-center gap-2 text-[10px] text-muted">
            <LegendSwatch color="bg-accent" label="PGs" />
            <LegendSwatch color="bg-err-soft border border-err/40" label="overload" />
            <LegendSwatch
              color="bg-warn-soft border border-warn/40"
              label="underload"
            />
          </div>
        </div>
        <div className="p-3 space-y-1.5">
          {osdEntries.map((o) => {
            const isOver = o.pgs >= overloadThresh;
            const isUnder = o.pgs <= underloadThresh;
            const pct = maxPg > 0 ? (o.pgs / maxPg) * 100 : 0;
            const targetPct = maxPg > 0 ? (target / maxPg) * 100 : 0;
            return (
              <button
                key={o.id}
                onClick={() =>
                  setSelectedOsd(selectedOsd === o.id ? null : o.id)
                }
                className={`w-full grid grid-cols-[140px_1fr_72px] items-center gap-2 px-1 py-0.5 rounded hover:bg-surface-2 text-left ${
                  selectedOsd === o.id ? "bg-accent-soft" : ""
                }`}
              >
                <div className="flex items-center gap-1.5 min-w-0">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${
                      o.online ? "bg-ok" : "bg-faint"
                    }`}
                  />
                  <span className="text-[11px] font-mono text-text-2 truncate">
                    {o.name}
                  </span>
                </div>
                <div className="relative h-4 bg-surface-2 rounded overflow-hidden">
                  <div
                    className={`absolute inset-y-0 left-0 ${
                      isOver
                        ? "bg-err"
                        : isUnder
                          ? "bg-warn-dot"
                          : "bg-accent"
                    }`}
                    style={{ width: `${pct}%` }}
                  />
                  {target > 0 && (
                    <div
                      className="absolute inset-y-0 w-px bg-text-2 opacity-60"
                      style={{ left: `${targetPct}%` }}
                      title={`target ${target.toFixed(1)}`}
                    />
                  )}
                </div>
                <div className="flex items-center justify-end gap-2 text-[11px] font-mono">
                  <span className={isOver ? "text-err font-semibold" : isUnder ? "text-warn font-semibold" : "text-text-2"}>
                    {o.pgs}
                  </span>
                  <span className="text-faint">·</span>
                  <span className="text-faint" title={`${o.shards} shards on disk`}>
                    {o.shards}s
                  </span>
                </div>
              </button>
            );
          })}
          {osdEntries.length === 0 && !loading && (
            <div className="text-center text-[12px] text-faint py-4">
              No active OSDs
            </div>
          )}
        </div>
      </div>

      {/* PG × OSD matrix */}
      <div className="bg-surface rounded-lg border border-border overflow-hidden mb-4">
        <div className="px-3 py-2 border-b border-border flex items-center justify-between">
          <h2 className="text-[12px] font-medium text-text-2 uppercase tracking-wide">
            PG × OSD matrix
          </h2>
          <div className="flex items-center gap-2 text-[10px] text-muted">
            {selectedOsd && (
              <button
                onClick={() => setSelectedOsd(null)}
                className="px-1.5 py-0.5 rounded bg-surface-2 hover:bg-border"
              >
                Clear OSD filter
              </button>
            )}
            {selectedPg !== null && (
              <button
                onClick={() => setSelectedPg(null)}
                className="px-1.5 py-0.5 rounded bg-surface-2 hover:bg-border"
              >
                Clear PG filter
              </button>
            )}
            <LegendSwatch color="bg-accent" label="acting" />
            <LegendSwatch color="bg-warn-dot" label="moving to" />
          </div>
        </div>
        <div className="overflow-auto" style={{ maxHeight: "480px" }}>
          <table className="text-[10px] border-collapse">
            <thead className="sticky top-0 bg-surface z-10">
              <tr>
                <th className="px-2 py-1 text-left text-muted font-normal sticky left-0 bg-surface z-20 border-b border-border">
                  pg_id
                </th>
                {osdEntries.map((o) => (
                  <th
                    key={o.id}
                    onClick={() =>
                      setSelectedOsd(selectedOsd === o.id ? null : o.id)
                    }
                    className={`px-1 py-1 text-center font-normal cursor-pointer border-b border-border ${
                      selectedOsd === o.id ? "bg-accent-soft text-accent" : "text-muted hover:bg-surface-2"
                    }`}
                    title={`${o.name} — ${o.pgs} PGs`}
                  >
                    <div className="font-mono">{o.name.replace("objectio-osd-", "osd")}</div>
                  </th>
                ))}
                <th className="px-2 py-1 text-center text-muted font-normal border-b border-border">
                  epoch
                </th>
              </tr>
            </thead>
            <tbody>
              {pgs.map((pg) => {
                const row = new Array(osdEntries.length).fill(
                  0,
                ) as Array<0 | 1 | 2>;
                const moving = movingTo(pg);
                pg.acting.forEach((osd) => {
                  const i = osdIndex.get(osd);
                  if (i !== undefined) row[i] = 1;
                });
                moving.forEach((osd) => {
                  const i = osdIndex.get(osd);
                  if (i !== undefined) row[i] = 2;
                });
                const hidden =
                  (selectedOsd &&
                    !pg.acting.includes(selectedOsd) &&
                    !moving.includes(selectedOsd)) ||
                  (selectedPg !== null && pg.pg_id !== selectedPg);
                if (hidden) return null;
                return (
                  <tr
                    key={pg.pg_id}
                    className={`hover:bg-surface-2 cursor-pointer ${
                      selectedPg === pg.pg_id ? "bg-accent-soft" : ""
                    }`}
                    onClick={() =>
                      setSelectedPg(selectedPg === pg.pg_id ? null : pg.pg_id)
                    }
                  >
                    <td className="px-2 py-0.5 font-mono text-text-2 sticky left-0 bg-surface z-10">
                      {pg.pg_id}
                    </td>
                    {row.map((v, i) => (
                      <td
                        key={i}
                        className="text-center"
                        title={v ? osdEntries[i].name : ""}
                      >
                        <div
                          className={`inline-block w-3 h-3 rounded-sm ${
                            v === 1
                              ? "bg-accent"
                              : v === 2
                                ? "bg-warn-dot"
                                : "bg-surface-2"
                          }`}
                        />
                      </td>
                    ))}
                    <td className="px-2 py-0.5 font-mono text-faint">
                      {pg.epoch}
                    </td>
                  </tr>
                );
              })}
              {pgs.length === 0 && !loading && (
                <tr>
                  <td
                    colSpan={osdEntries.length + 2}
                    className="px-3 py-6 text-center text-faint"
                  >
                    No placement groups in this pool
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/** One PG: its members and what each lacks, recovery, and its scrub. */
function PgDetail({
  pg,
  osdName,
  onScrub,
  note,
}: {
  pg: PlacementGroup;
  osdName: Map<string, string>;
  onScrub: () => void;
  note: string | null;
}) {
  const st = pg.state;
  const name = (id: string) => osdName.get(id) ?? id.slice(0, 8);
  const member = new Map((st?.members ?? []).map((m) => [m.position, m]));
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[13px] font-semibold text-text">PG {pg.pg_id}</span>
          <span className={`px-1 py-px rounded border text-[10px] ${stateTone(stateOf(pg))}`}>
            {stateOf(pg)}
          </span>
          <span className="text-faint">epoch {pg.epoch}</span>
          {st && <span className="text-faint">since {ago(st.since)}</span>}
        </div>
        <button
          onClick={onScrub}
          className="flex items-center gap-1 px-2 py-0.5 border border-border rounded text-[11px] text-text-2 hover:bg-surface-2"
        >
          <ScanSearch size={12} />
          Scrub now
        </button>
      </div>
      {note && <div className="text-[11px] text-muted">{note}</div>}
      {st?.last_error && (
        <div className="rounded border border-warn/30 bg-warn-soft px-2 py-1 text-warn">
          {st.last_error}
        </div>
      )}
      {st && (
        <div className="grid grid-cols-3 gap-x-3 gap-y-0.5 text-text-2">
          <span>objects {st.objects}</span>
          <span>degraded {st.objects_degraded}</span>
          <span className={st.objects_unfound ? "text-err font-semibold" : ""}>
            unfound {st.objects_unfound}
          </span>
          <span>copies missing {st.copies_missing}</span>
          <span>copies stale {st.copies_stale}</span>
          <span>shards missing {st.shards_missing}</span>
        </div>
      )}
      <table className="w-full">
        <thead className="text-muted">
          <tr className="border-b border-border">
            <th className="text-left font-normal py-0.5">Pos</th>
            <th className="text-left font-normal">OSD</th>
            <th className="text-right font-normal">Missing</th>
            <th className="text-right font-normal">Stale</th>
            <th className="text-right font-normal">Shards</th>
          </tr>
        </thead>
        <tbody>
          {pg.acting.map((id, pos) => {
            const m = member.get(pos);
            const up = pg.up[pos];
            const filling = pg.filling.find((f) => f.position === pos);
            return (
              <tr key={pos}>
                <td className="font-mono py-0.5">{pos}</td>
                <td className="font-mono">
                  <span className={m && !m.answered ? "text-err" : ""}>{id ? name(id) : "—"}</span>
                  {up && up !== id && <span className="text-warn"> → {name(up)}</span>}
                  {filling && <span className="text-accent"> (filling from {name(filling.from)})</span>}
                  {m && !m.answered && <span className="text-err"> down</span>}
                </td>
                <td className="text-right font-mono">{m?.copies_missing ?? "–"}</td>
                <td className="text-right font-mono">{m?.copies_stale ?? "–"}</td>
                <td className="text-right font-mono">{m?.shards_missing ?? "–"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {st && (st.recovery.remaining > 0 || st.recovery.recovered > 0) && (
        <div className="text-text-2">
          recovery: {st.recovery.recovered} done, {st.recovery.remaining} left (
          {bytes(st.recovery.bytes_remaining)}), at {st.recovery.cursor || "the start"}
          {st.recovery.reserved_on.length > 0 &&
            `, reserved on ${st.recovery.reserved_on.length} OSDs`}
        </div>
      )}
      {st && st.recovery.unfound_keys.length > 0 && (
        <div className="text-err">unfound: {st.recovery.unfound_keys.join(", ")}</div>
      )}
      <div className="text-text-2">
        scrub:{" "}
        {pg.scrub?.running
          ? `running (${pg.scrub.members_done.length} of ${pg.acting.length} members through, ${bytes(pg.scrub.bytes)} read, ${pg.scrub.bad} bad)`
          : pg.scrub?.requested
            ? "requested"
            : `last completed ${ago(pg.scrub?.last_complete ?? 0)}`}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  hint,
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="bg-surface rounded-lg border border-border px-3 py-2.5">
      <div className="flex items-center gap-1.5 text-[10px] text-muted uppercase tracking-wide">
        {icon}
        {label}
      </div>
      <div className="text-[18px] font-semibold text-text mt-0.5">
        {value}
      </div>
      {hint && <div className="text-[10px] text-faint mt-0.5">{hint}</div>}
    </div>
  );
}

function LegendSwatch({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className={`w-2.5 h-2.5 rounded-sm ${color}`} />
      {label}
    </span>
  );
}
