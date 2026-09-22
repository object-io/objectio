import { NavLink, Outlet } from "react-router-dom";
import {
  LayoutDashboard,
  Archive,
  Users,
  UserCircle,
  Shield,
  Fingerprint,
  Table2,
  Database,
  Share2,
  Activity,
  Box,
  Layers,
  Building2,
  KeyRound,
  LogOut,
} from "lucide-react";
import appIcon from "../assets/brand/app-icon.svg";

interface NavItem {
  to: string;
  icon: typeof LayoutDashboard;
  label: string;
  adminOnly?: boolean;
}

const nav: NavItem[] = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/buckets", icon: Archive, label: "Buckets" },
  { to: "/objects", icon: Box, label: "Object Browser" },
  // Cluster bundles Topology + Nodes & Drives + Storage Pools +
  // Balancing into a tabbed view. The legacy /pools, /topology,
  // /drives routes redirect here for bookmark back-compat.
  { to: "/cluster", icon: Layers, label: "Cluster", adminOnly: true },
  { to: "/tenants", icon: Building2, label: "Tenants", adminOnly: true },
  { to: "/users", icon: Users, label: "Users" },
  { to: "/policies", icon: Shield, label: "Policies" },
  { to: "/identity", icon: Fingerprint, label: "Identity" },
  { to: "/iceberg", icon: Table2, label: "Tables" },
  { to: "/unity", icon: Database, label: "Unity Catalog" },
  { to: "/sharing", icon: Share2, label: "Table Sharing" },
  { to: "/monitoring", icon: Activity, label: "Monitoring", adminOnly: true },
  { to: "/encryption", icon: KeyRound, label: "Encryption", adminOnly: true },
];

interface Props {
  user?: string;
  tenant?: string;
  onLogout?: () => void;
}

export default function Layout({ user, tenant, onLogout }: Props) {
  const isSystemAdmin = !tenant;
  const visibleNav = nav.filter((n) => !n.adminOnly || isSystemAdmin);

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="w-[208px] bg-sidebar border-r border-border flex flex-col shrink-0">
        {/* Brand block. Black is the icon tile only — the sidebar itself
            stays white. An inverted full-width band reads as a title bar and
            is not what the artboard does. */}
        <div className="flex items-center gap-2 px-3.5 h-[60px] border-b border-border">
          <img
            src={appIcon}
            alt=""
            aria-hidden
            className="w-[32px] h-[32px] shrink-0 select-none"
            draggable={false}
          />
          <span className="min-w-0">
            <span className="block font-display text-[16px] leading-none font-semibold text-text">
              Object<span className="text-accent-ring">IO</span>
            </span>
            <span className="block mt-1 font-mono text-[10px] uppercase tracking-[0.14em] text-muted">
              {isSystemAdmin ? "Ops console" : "Console"}
            </span>
          </span>
        </div>
        <nav className="flex-1 px-2 py-2.5 space-y-0.5 overflow-y-auto">
          {visibleNav.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 h-9 rounded-[10px] text-[13px] transition-colors ${
                  isActive
                    ? "bg-accent-soft text-accent font-medium"
                    : "text-text hover:bg-surface-2"
                }`
              }
            >
              <Icon size={16} className="shrink-0" />
              <span className="flex-1 min-w-0 truncate">{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="px-2 py-2 border-t border-border">
          {user && onLogout ? (
            // The user panel doubles as the entry point to My Account — clicking
            // the name/tenant block opens the profile page; Sign-out is a
            // separate icon so it's always one click away.
            <div className="flex items-center justify-between gap-1">
              <NavLink
                to="/account"
                className={({ isActive }) =>
                  `flex items-center gap-2 flex-1 min-w-0 px-1.5 py-1 rounded-control transition-colors ${
                    isActive
                      ? "bg-accent-soft text-accent"
                      : "text-text-2 hover:bg-surface-2 hover:text-text"
                  }`
                }
                title="My account"
              >
                <UserCircle size={15} className="shrink-0" />
                <div className="min-w-0 truncate">
                  <span className="block text-[11px] font-medium truncate">{user}</span>
                  <span className="block text-[10px] text-muted truncate">
                    {tenant || "system admin"}
                  </span>
                </div>
              </NavLink>
              <button
                onClick={onLogout}
                className="text-faint hover:text-text p-1.5 rounded-control hover:bg-surface-2"
                title="Sign out"
              >
                <LogOut size={13} />
              </button>
            </div>
          ) : (
            <span className="text-[10px] text-faint">ObjectIO v0.1.0</span>
          )}
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto bg-bg">
        <Outlet />
      </main>
    </div>
  );
}
