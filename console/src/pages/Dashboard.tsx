import { useEffect, useState } from "react";
import {
  HardDrive,
  Database,
  Users,
  Table2,
  Activity,
  CheckCircle,
  AlertCircle,
} from "lucide-react";
import Card from "../components/Card";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import { cluster, users, iceberg } from "../api/client";

interface Metric {
  label: string;
  value: string;
  icon: React.ElementType;
  color: string;
}

function StatCard({ label, value, icon: Icon, color }: Metric) {
  return (
    <div className="bg-surface rounded-xl border border-border p-4">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-[11px] text-muted uppercase tracking-wider font-medium">{label}</p>
          <p className="text-xl font-semibold text-text mt-1">{value}</p>
        </div>
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${color}`}>
          <Icon size={16} className="text-primary-fg" />
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [bucketCount, setBucketCount] = useState("-");
  const [userCount, setUserCount] = useState("-");
  const [nsCount, setNsCount] = useState("-");
  const [metrics, setMetrics] = useState("");

  useEffect(() => {
    cluster.health().then(setHealthy).catch(() => setHealthy(false));
    fetch("/_admin/buckets").then(r => r.json()).then(d => setBucketCount(String(d.buckets?.length || 0))).catch(() => {});
    users.list().then((u) => setUserCount(String(u.users?.length || 0))).catch(() => {});
    iceberg.listNamespaces().then((r) => setNsCount(String(r.namespaces?.length || 0))).catch(() => {});
    cluster.metrics().then(setMetrics).catch(() => {});
  }, []);

  const parseMetric = (name: string): string => {
    const match = metrics.match(new RegExp(`^${name}\\s+(\\S+)`, "m"));
    return match ? match[1] : "-";
  };

  const stats: Metric[] = [
    { label: "Buckets", value: bucketCount, icon: Database, color: "bg-accent" },
    { label: "Users", value: userCount, icon: Users, color: "bg-purple-500" },
    { label: "Iceberg Namespaces", value: nsCount, icon: Table2, color: "bg-emerald-500" },
    { label: "S3 Requests", value: parseMetric("objectio_s3_requests_total"), icon: Activity, color: "bg-orange-500" },
  ];

  return (
    <div className="p-6">
      <PageHeader
        title="Dashboard"
        description="Cluster overview and health status"
      />

      {/* Health banner */}
      <div
        className={`mb-4 rounded-xl border p-3 flex items-center gap-3 ${
          healthy === true
            ? "bg-green-50 border-green-200"
            : healthy === false
              ? "bg-red-50 border-red-200"
              : "bg-surface-2 border-border"
        }`}
      >
        {healthy === true ? (
          <CheckCircle className="text-green-600" size={16} />
        ) : healthy === false ? (
          <AlertCircle className="text-red-600" size={16} />
        ) : (
          <Activity className="text-faint animate-spin" size={16} />
        )}
        <span className="text-[13px] font-medium">
          {healthy === true
            ? "All systems operational"
            : healthy === false
              ? "Gateway unreachable"
              : "Checking..."}
        </span>
        <StatusBadge
          status={healthy === true ? "healthy" : healthy === false ? "error" : "unknown"}
        />
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
        {stats.map((s) => (
          <StatCard key={s.label} {...s} />
        ))}
      </div>

      {/* Cluster info */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card title="Cluster Configuration">
          <dl className="space-y-2.5 text-[13px]">
            <div className="flex justify-between">
              <dt className="text-muted">Erasure Coding</dt>
              <dd className="font-medium">3+2 (Reed-Solomon)</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-muted">OSDs</dt>
              <dd className="font-medium">5</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-muted">Region</dt>
              <dd className="font-medium">us-east-1</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-muted">Gateway</dt>
              <dd>
                <StatusBadge status={healthy ? "healthy" : "error"} label={healthy ? "Running" : "Down"} />
              </dd>
            </div>
          </dl>
        </Card>

        <Card title="Services">
          <div className="space-y-2.5">
            {[
              { name: "S3 Gateway", port: 9000, status: healthy },
              { name: "Metadata (Raft)", port: 9100, status: true },
              { name: "Iceberg REST Catalog", port: 9000, status: true },
              { name: "Delta Sharing", port: 9000, status: true },
            ].map((svc) => (
              <div key={svc.name} className="flex items-center justify-between text-[13px]">
                <div className="flex items-center gap-2">
                  <HardDrive size={13} className="text-faint" />
                  <span>{svc.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-faint font-mono text-[11px]">:{svc.port}</span>
                  <StatusBadge
                    status={svc.status ? "healthy" : "error"}
                    label={svc.status ? "Running" : "Down"}
                  />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
}
