import { useEffect, useState } from "react";
import { Pause, Play, RefreshCw, Save } from "lucide-react";
import { rebalance as rebalanceApi, type RebalanceStatus, request } from "../api/client";
import { Banner, Button, StatTile } from "../components/ui";

/// Balancing tab — live PG balancer status + tuning knobs.
///
/// The balancer re-reads these config keys on every tick, so a
/// save round-trips through Meta's Raft and takes effect within
/// one sweep (default 60s). No restart required.

interface KnobDef {
  key: string;
  label: string;
  hint: string;
  type: "number" | "bool";
  min?: number;
  max?: number;
  step?: number;
  placeholder?: string;
}

const KNOBS: KnobDef[] = [
  {
    key: "balancer/sweep_interval_seconds",
    label: "Tick interval (s)",
    hint: "How often the balancer evaluates. Clamped 5–3600.",
    type: "number",
    min: 5,
    max: 3600,
    step: 1,
    placeholder: "60",
  },
  {
    key: "balancer/overload_multiplier",
    label: "Overload multiplier",
    hint: "Trigger a move when any OSD holds ≥ this × target PGs. Default 1.20.",
    type: "number",
    min: 1.0,
    max: 5.0,
    step: 0.05,
    placeholder: "1.20",
  },
  {
    key: "balancer/underload_multiplier",
    label: "Underload multiplier",
    hint: "Also trigger when any OSD is ≤ this × target. 0 disables. Default 0.70.",
    type: "number",
    min: 0,
    max: 1.0,
    step: 0.05,
    placeholder: "0.70",
  },
  {
    key: "balancer/improvement_factor",
    label: "Improvement factor",
    hint: "Move commits only if candidate's total load ≤ factor × current. Default 0.90 (≥10% better).",
    type: "number",
    min: 0.0,
    max: 1.0,
    step: 0.01,
    placeholder: "0.90",
  },
  {
    key: "balancer/scatter_width",
    label: "Scatter width",
    hint: "Copyset-pool diversity target (Cidon/Stutsman). Default 10.",
    type: "number",
    min: 1,
    max: 100,
    step: 1,
    placeholder: "10",
  },
  {
    key: "balancer/per_tick_cap",
    label: "Per-tick cap",
    hint: "Max moves per pool per tick. 0 = auto (max(3, osds/3)).",
    type: "number",
    min: 0,
    max: 1000,
    step: 1,
    placeholder: "0",
  },
  {
    key: "balancer/paused",
    label: "Paused",
    hint: "Halt all balancer commits. Ticks still run so logs stay fresh.",
    type: "bool",
  },
];

export default function Balancing() {
  const [status, setStatus] = useState<RebalanceStatus | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [saved, setSaved] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const loadStatus = async () => {
    try {
      const s = await rebalanceApi.status();
      setStatus(s);
    } catch (e) {
      setErr(String(e));
    }
  };

  const loadKnobs = async () => {
    // One GET /_admin/config returns every config entry; we filter
    // the ones that start with balancer/ and seed both values and
    // "saved" (so we can tell if there are unsaved edits).
    try {
      const all = await request<
        Array<{ key: string; value: unknown; version: number }>
      >("GET", "/_admin/config");
      const next: Record<string, string> = {};
      for (const e of all) {
        if (!e.key.startsWith("balancer/")) continue;
        // Values are stored as raw JSON — unwrap the common
        // {"value":"..."} shape the generic PUT handler wrote.
        const raw =
          typeof e.value === "object" && e.value !== null && "value" in e.value
            ? (e.value as { value: unknown }).value
            : e.value;
        next[e.key] = String(raw ?? "");
      }
      setValues(next);
      setSaved(next);
    } catch (e) {
      setErr(String(e));
    }
  };

  useEffect(() => {
    loadStatus();
    loadKnobs();
    // Status poll — balancer ticks every 60s by default, so 5s is
    // plenty granular to show progress without hammering the API.
    const h = setInterval(loadStatus, 5000);
    return () => clearInterval(h);
  }, []);

  const saveOne = async (k: string, v: string) => {
    setSaving(k);
    setErr(null);
    try {
      // The server validates the body as JSON; send raw numbers /
      // booleans so the balancer's parse::<f64>()/parse::<u64>()
      // sees a clean value, not a {"value":"0.95"} wrapper.
      const body =
        KNOBS.find((x) => x.key === k)?.type === "bool"
          ? v === "true"
            ? "true"
            : "false"
          : v;
      await request(`PUT`, `/_admin/config/${k}`, body);
      setSaved((s) => ({ ...s, [k]: v }));
      // A knob change may flip paused — refresh status immediately.
      loadStatus();
    } catch (e) {
      setErr(String(e));
    } finally {
      setSaving(null);
    }
  };

  const tiles = [
    { label: "PG moves total", value: (status?.pgs_moved_total ?? 0).toLocaleString() },
    {
      label: "Scanned last tick",
      value: (status?.pgs_scanned_last_tick ?? 0).toLocaleString(),
      sub: "PGs",
    },
    {
      label: "Candidates pending",
      value: (status?.pg_candidates_last_tick ?? 0).toLocaleString(),
    },
    {
      label: "Last tick",
      value: status?.last_sweep_at
        ? new Date(status.last_sweep_at * 1000).toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
          })
        : "—",
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <Banner
        kind={status?.paused ? "err" : status?.started ? "info" : "warn"}
        title={`Balancer ${status?.paused ? "paused" : status?.started ? "running" : "idle"}`}
        action={
          <Button
            size="sm"
            variant="secondary"
            icon={status?.paused ? <Play size={12} /> : <Pause size={12} />}
            disabled={!status}
            onClick={() => saveOne("balancer/paused", status?.paused ? "false" : "true")}
          >
            {status?.paused ? "Resume" : "Pause"}
          </Button>
        }
      >
        {status
          ? status.paused
            ? "Ticks still run so the logs stay fresh, but no move is committed."
            : "Moves commit through Raft; a knob change takes effect on the next sweep."
          : "Loading…"}
        {status?.last_error && <> · last error: {status.last_error}</>}
      </Banner>

      {err && <Banner kind="err">{err}</Banner>}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {tiles.map((t) => (
          <StatTile key={t.label} label={t.label} value={t.value} sub={t.sub} />
        ))}
      </div>

      <div className="bg-surface border border-border rounded-card shadow-sm overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-muted">Tuning</h3>
          <Button size="sm" variant="ghost" icon={<RefreshCw size={12} />} onClick={loadKnobs}>
            Reload
          </Button>
        </div>
        <div>
          {KNOBS.map((k) => {
            const cur = values[k.key] ?? "";
            const sv = saved[k.key] ?? "";
            const dirty = cur !== sv;
            return (
              <div
                key={k.key}
                className="flex items-center gap-3 px-4 py-2.5 border-t border-border first:border-t-0"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-[12px] font-medium text-text">
                    {k.label}
                    <span className="ml-1.5 font-mono text-[10px] text-faint">{k.key}</span>
                  </p>
                  <p className="text-[11px] text-muted mt-0.5">{k.hint}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {k.type === "bool" ? (
                    <select
                      value={cur || "false"}
                      onChange={(e) => setValues((s) => ({ ...s, [k.key]: e.target.value }))}
                      className="h-8 px-2 bg-surface text-text border border-border-strong
                        rounded-control text-[12px] font-mono w-28 focus:outline-none focus:border-accent"
                    >
                      <option value="false">false</option>
                      <option value="true">true</option>
                    </select>
                  ) : (
                    <input
                      type="number"
                      min={k.min}
                      max={k.max}
                      step={k.step}
                      value={cur}
                      placeholder={k.placeholder}
                      onChange={(e) => setValues((s) => ({ ...s, [k.key]: e.target.value }))}
                      className="h-8 px-2 bg-surface text-text border border-border-strong
                        rounded-control text-[12px] font-mono w-28 focus:outline-none focus:border-accent"
                    />
                  )}
                  <Button
                    size="sm"
                    variant={dirty ? "accent" : "secondary"}
                    icon={<Save size={11} />}
                    disabled={!dirty || saving === k.key}
                    onClick={() => saveOne(k.key, cur)}
                  >
                    {saving === k.key ? "Saving…" : dirty ? "Save" : "Saved"}
                  </Button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <p className="text-[11px] text-muted">
        Knobs hot-reload through Raft — no restart. A tick-interval change lands
        on the next sweep.
      </p>
    </div>
  );
}
