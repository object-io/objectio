import { useEffect, useMemo, useState } from "react";
import { X, Filter, Plus, Trash2 } from "lucide-react";
import { unity } from "../api/client";
import type {
  UnityColumnInfo,
  UnityColumnMask,
  UnityFunctionInfo,
  UnityRowFilter,
  UnityTableInfo,
} from "../api/client";

/// Modal editor for a Unity table's row-filter and per-column-mask
/// bindings. Engines (Spark/Trino) read these from the table metadata
/// and inject `WHERE function(input_columns)` / `mask_function(col, …)`
/// at query time.
///
/// Only functions in the same catalog.schema can be referenced; row
/// filters must be SQL UDFs returning BOOLEAN, masks must return the
/// masked column's type (the gateway enforces both at PUT).
interface Props {
  catalog: string;
  schema: string;
  table: string;
  onClose: () => void;
  /// Called on successful save with the refreshed TableInfo so the
  /// parent can update its row in-place without a full re-fetch.
  onSaved?: (info: UnityTableInfo) => void;
}

interface MaskRow {
  column: string;
  function_full_name: string;
  using_column_names: string[];
}

export default function TableSecurityEditor({
  catalog,
  schema,
  table,
  onClose,
  onSaved,
}: Props) {
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [columns, setColumns] = useState<UnityColumnInfo[]>([]);
  const [functions, setFunctions] = useState<UnityFunctionInfo[]>([]);

  const [rowFilterFn, setRowFilterFn] = useState<string>("");
  const [rowFilterCols, setRowFilterCols] = useState<string>("");

  const [masks, setMasks] = useState<MaskRow[]>([]);

  // Initial load: pull the table (for current bindings + columns) and
  // the schema's functions (the candidate set for both bindings).
  useEffect(() => {
    let alive = true;
    Promise.all([
      unity.getTable(catalog, schema, table),
      unity.listFunctions(catalog, schema),
    ])
      .then(([t, fs]) => {
        if (!alive) return;
        setColumns(t.columns ?? []);
        setFunctions(fs.functions ?? []);
        if (t.row_filter) {
          setRowFilterFn(t.row_filter.function_full_name);
          setRowFilterCols((t.row_filter.input_column_names ?? []).join(", "));
        }
        const cm = t.column_masks ?? {};
        setMasks(
          Object.entries(cm).map(([col, m]) => ({
            column: col,
            function_full_name: m.function_full_name,
            using_column_names: m.using_column_names ?? [],
          })),
        );
      })
      .catch((e: Error) => alive && setError(e.message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [catalog, schema, table]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const fnNames = useMemo(
    () => functions.map((f) => f.full_name ?? `${catalog}.${schema}.${f.name}`),
    [functions, catalog, schema],
  );
  const colNames = useMemo(() => columns.map((c) => c.name), [columns]);

  const addMask = () => {
    setMasks((m) => [
      ...m,
      { column: "", function_full_name: "", using_column_names: [] },
    ]);
  };

  const updateMask = (i: number, patch: Partial<MaskRow>) => {
    setMasks((m) => m.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  };

  const removeMask = (i: number) => {
    setMasks((m) => m.filter((_, j) => j !== i));
  };

  const onSave = async () => {
    setError(null);

    let row_filter: UnityRowFilter | null = null;
    if (rowFilterFn.trim() !== "") {
      row_filter = {
        function_full_name: rowFilterFn.trim(),
        input_column_names: rowFilterCols
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };
    }

    const column_masks: Record<string, UnityColumnMask> = {};
    for (const m of masks) {
      const col = m.column.trim();
      const fn = m.function_full_name.trim();
      if (!col || !fn) continue;
      if (column_masks[col]) {
        setError(`Duplicate mask for column "${col}".`);
        return;
      }
      column_masks[col] = {
        function_full_name: fn,
        using_column_names: m.using_column_names.filter(Boolean),
      };
    }

    setBusy(true);
    try {
      const info = await unity.setTableSecurity(catalog, schema, table, {
        row_filter,
        column_masks,
      });
      onSaved?.(info);
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 bg-black/30 z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-surface rounded-xl shadow-xl w-full max-w-3xl max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between px-5 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <Filter size={16} className="text-ok" />
            <div>
              <h2 className="text-[14px] font-semibold text-text">
                Row filter & column masks
              </h2>
              <div className="text-[12px] text-muted font-mono">
                {catalog}.{schema}.{table}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-faint hover:text-text-2 p-1 rounded hover:bg-surface-2"
          >
            <X size={14} />
          </button>
        </div>

        <div className="px-5 py-3 text-[12px] text-text-2 border-b border-border">
          Functions are looked up in the same schema. Row filter must be a
          SQL UDF returning BOOLEAN; masks must return the masked column's
          type. Clear by leaving fields empty.
        </div>

        {loading ? (
          <div className="p-8 text-center text-[12px] text-faint">
            Loading…
          </div>
        ) : (
          <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
            {/* Row filter */}
            <section>
              <div className="text-[11px] font-medium text-muted uppercase tracking-wider mb-2">
                Row filter
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[11px] text-muted mb-1">
                    Filter function
                  </label>
                  <select
                    value={rowFilterFn}
                    onChange={(e) => setRowFilterFn(e.target.value)}
                    className="w-full px-2.5 py-1.5 border border-border-strong rounded-lg text-[12px] font-mono"
                  >
                    <option value="">— none —</option>
                    {fnNames.map((n) => (
                      <option key={n} value={n}>
                        {n}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-[11px] text-muted mb-1">
                    Input columns (comma-separated)
                  </label>
                  <input
                    value={rowFilterCols}
                    onChange={(e) => setRowFilterCols(e.target.value)}
                    placeholder="region, tenant_id"
                    disabled={rowFilterFn === ""}
                    className="w-full px-2.5 py-1.5 border border-border-strong rounded-lg text-[12px] font-mono disabled:bg-surface-2 disabled:text-faint"
                  />
                </div>
              </div>
            </section>

            {/* Column masks */}
            <section>
              <div className="flex items-center justify-between mb-2">
                <div className="text-[11px] font-medium text-muted uppercase tracking-wider">
                  Column masks
                </div>
                <button
                  onClick={addMask}
                  className="flex items-center gap-1 px-2 py-1 border border-border-strong rounded text-[11px] text-text-2 hover:bg-surface-2"
                >
                  <Plus size={12} /> Add mask
                </button>
              </div>
              {masks.length === 0 ? (
                <div className="text-[12px] text-faint py-3 text-center border border-dashed border-border rounded">
                  No column masks. Click <span className="font-medium">Add mask</span> to bind one.
                </div>
              ) : (
                <div className="space-y-2">
                  {masks.map((m, i) => (
                    <div
                      key={i}
                      className="grid grid-cols-[1fr_1.5fr_1.5fr_auto] gap-2 items-end border border-border rounded-lg p-2"
                    >
                      <div>
                        <label className="block text-[10px] text-muted mb-1">
                          Column
                        </label>
                        <select
                          value={m.column}
                          onChange={(e) =>
                            updateMask(i, { column: e.target.value })
                          }
                          className="w-full px-2 py-1 border border-border-strong rounded text-[12px] font-mono"
                        >
                          <option value="">—</option>
                          {colNames.map((c) => (
                            <option key={c} value={c}>
                              {c}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="block text-[10px] text-muted mb-1">
                          Mask function
                        </label>
                        <select
                          value={m.function_full_name}
                          onChange={(e) =>
                            updateMask(i, {
                              function_full_name: e.target.value,
                            })
                          }
                          className="w-full px-2 py-1 border border-border-strong rounded text-[12px] font-mono"
                        >
                          <option value="">—</option>
                          {fnNames.map((n) => (
                            <option key={n} value={n}>
                              {n}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="block text-[10px] text-muted mb-1">
                          Using columns (comma-separated)
                        </label>
                        <input
                          value={m.using_column_names.join(", ")}
                          onChange={(e) =>
                            updateMask(i, {
                              using_column_names: e.target.value
                                .split(",")
                                .map((s) => s.trim())
                                .filter(Boolean),
                            })
                          }
                          placeholder="role, tenant_id"
                          className="w-full px-2 py-1 border border-border-strong rounded text-[12px] font-mono"
                        />
                      </div>
                      <button
                        onClick={() => removeMask(i)}
                        className="p-1.5 text-faint hover:text-err"
                        title="Remove mask"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>

            {functions.length === 0 && (
              <div className="text-[12px] text-warn bg-warn-soft border border-warn/25 rounded p-2">
                No functions in <span className="font-mono">{catalog}.{schema}</span>.
                Create one (Functions tab) before binding security.
              </div>
            )}
          </div>
        )}

        {error && (
          <div className="px-5 py-2 bg-err-soft border-t border-err/25 text-[12px] text-err font-mono break-all">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2 px-5 py-3 border-t border-border bg-surface-2 rounded-b-xl">
          <button
            onClick={onClose}
            className="px-3 py-1.5 border border-border-strong text-text-2 rounded-lg text-[12px] font-medium hover:bg-surface"
          >
            Cancel
          </button>
          <button
            onClick={onSave}
            disabled={busy || loading}
            className="px-3 py-1.5 bg-primary text-primary-fg rounded-lg text-[12px] font-medium hover:bg-primary-hover disabled:opacity-50"
          >
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
