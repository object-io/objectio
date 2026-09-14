import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Plus, RefreshCw } from "lucide-react";
import PageHeader from "../components/PageHeader";
import { Button, Tabs } from "../components/ui";
import { nodes as nodesApi, type NodeInfo } from "../api/client";
import Topology from "./Topology";
import Drives from "./Drives";
import Pools from "./Pools";
import Balancing from "./Balancing";

type TabKey = "topology" | "drives" | "pools" | "balancing";

const TABS: Array<{ key: TabKey; label: string }> = [
  { key: "topology", label: "Topology" },
  { key: "drives", label: "Nodes & drives" },
  { key: "pools", label: "Storage pools" },
  { key: "balancing", label: "Balancing" },
];

/// Unified /cluster page. Tabs map to URL params (`/cluster/:tab`) so deep
/// links to a specific view still work — the old `/topology`, `/drives` and
/// `/pools` routes redirect here via App.tsx.
export default function Cluster() {
  const nav = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  const [hosts, setHosts] = useState<NodeInfo[]>([]);
  const [reloadKey, setReloadKey] = useState(0);

  const active: TabKey = useMemo(() => {
    const valid = TABS.map((t) => t.key);
    return (valid.includes(urlTab as TabKey) ? urlTab : "topology") as TabKey;
  }, [urlTab]);

  const loadHosts = useCallback(() => {
    nodesApi.list().then((d) => setHosts(d.nodes ?? [])).catch(() => setHosts([]));
  }, []);

  useEffect(() => {
    // Normalise the URL so refresh lands on the same tab.
    if (!urlTab) nav("/cluster/topology", { replace: true });
  }, [urlTab, nav]);

  useEffect(() => {
    loadHosts();
  }, [loadHosts, reloadKey]);

  // Host health summarised in the header, so the state of the cluster is
  // visible from every tab rather than only the one that happens to list it.
  // "warn" is a host that is up but has a disk reporting something other than
  // healthy — degraded but still serving, which neither up nor down conveys.
  const up = hosts.filter((h) => h.online).length;
  const warn = hosts.filter(
    (h) => h.online && (h.disks ?? []).some((d) => d.status && d.status !== "healthy")
  ).length;
  const down = hosts.length - up;

  return (
    <div className="p-6">
      <PageHeader
        title="Cluster"
        description="Topology, nodes, pools and placement"
        action={
          <div className="flex items-center gap-4">
            <div className="hidden sm:flex items-center gap-3 text-[12px]">
              <span className="inline-flex items-center gap-1.5 text-text-2">
                <span className="w-[6px] h-[6px] rounded-full bg-ok" />
                {up} host{up === 1 ? "" : "s"} up
              </span>
              <span className="inline-flex items-center gap-1.5 text-text-2">
                <span className="w-[6px] h-[6px] rounded-full bg-warn-dot" />
                {warn} warn
              </span>
              <span className="inline-flex items-center gap-1.5 text-text-2">
                <span className="w-[6px] h-[6px] rounded-full bg-err" />
                {down} down
              </span>
            </div>
            <div className="flex gap-2">
              <Button
                variant="secondary"
                icon={<RefreshCw size={13} />}
                onClick={() => setReloadKey((k) => k + 1)}
              >
                Refresh
              </Button>
              <Button
                variant="secondary"
                icon={<Plus size={13} />}
                onClick={() => nav("/cluster/drives")}
              >
                Add host
              </Button>
            </div>
          </div>
        }
      />

      <Tabs
        variant="underline"
        value={active}
        onChange={(k) => nav(`/cluster/${k}`)}
        items={TABS}
        className="mb-5"
      />

      <div key={reloadKey}>
        {active === "topology" && <Topology embedded />}
        {active === "drives" && <Drives embedded />}
        {active === "pools" && <Pools embedded />}
        {active === "balancing" && <Balancing />}
      </div>
    </div>
  );
}
