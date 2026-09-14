import { useEffect, useState } from "react";
import { LogIn, Lock, User, Building2 } from "lucide-react";
import mark from "../assets/brand/mark-light.svg";
import { Button, Input, Banner } from "../components/ui";

interface Props {
  onLogin: (user: string, tenant: string) => void;
  /// Which bundle is rendering this Login. Lets us tweak the Account
  /// field's required/optional treatment without forcing two copies of
  /// the page. Defaults to "ops" so older callers (and the legacy
  /// single-bundle build) keep their current behavior.
  appKind?: "ops" | "tenant";
}

interface TenantSso {
  tenant: string;
  display_name: string;
  sso_enabled: boolean;
  provider_name?: string;
}

/// Console sign-in. The real auth flow is access-key + secret — Username
/// and Password fields map to those.
///
/// AWS-style tenant scoping: a `?tenant=NAME` URL query (or the Account
/// input below) scopes both AK/SK and SSO to that tenant. The SSO button
/// then shows only the tenant's own provider, not the system providers.
export default function Login({ onLogin, appKind = "ops" }: Props) {
  const tenantApp = appKind === "tenant";
  const [accessKey, setAccessKey] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [oidcEnabled, setOidcEnabled] = useState(false);
  const [providers, setProviders] = useState<
    { name: string; label: string }[]
  >([]);

  // Tenant scoping. `tenantInput` is what the user typed (or pre-filled
  // from ?tenant=). `tenantSso` is the resolved server response that
  // tells us whether to show a tenant-specific SSO button. Empty input =
  // system-wide login (no tenant scoping; system SSO providers visible).
  const [tenantInput, setTenantInput] = useState("");
  const [tenantSso, setTenantSso] = useState<TenantSso | null>(null);
  const [tenantLookupError, setTenantLookupError] = useState("");

  useEffect(() => {
    fetch("/_console/api/oidc/enabled")
      .then((r) => r.json())
      .then((d) => {
        setOidcEnabled(d.enabled === true);
        setProviders(d.providers || []);
      })
      .catch(() => setOidcEnabled(false));

    const params = new URLSearchParams(window.location.search);
    const err = params.get("error");
    if (err) {
      setError(err);
      window.history.replaceState({}, "", window.location.pathname);
    }
    // Tenant scoping is meaningless on the operator console — a system
    // admin has no tenant, and a tenant session would be refused here by
    // the audience gate anyway. Ignoring the query keeps a stray
    // ?tenant= from applying a scope the user cannot see.
    const t = params.get("tenant");
    if (t && tenantApp) {
      setTenantInput(t);
      lookupTenant(t);
    }
    // Runs once on mount. `tenantApp` is derived from the bundle's own
    // appKind prop and cannot change for the life of the component.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Resolve the tenant's SSO config. Called on URL pre-fill and on
  // input blur so we don't fire a request on every keystroke.
  const lookupTenant = async (name: string) => {
    setTenantLookupError("");
    setTenantSso(null);
    if (!name.trim()) return;
    try {
      const r = await fetch(`/_console/api/tenant/${encodeURIComponent(name)}/sso`);
      if (r.status === 404) {
        setTenantLookupError(`Tenant "${name}" not found`);
        return;
      }
      if (!r.ok) {
        setTenantLookupError(`Tenant lookup failed (${r.status})`);
        return;
      }
      setTenantSso(await r.json());
    } catch {
      setTenantLookupError("Tenant lookup failed");
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const resp = await fetch("/_console/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          accessKey,
          secretKey,
          // Forward the account input only when supplied. Backend
          // refuses login if the typed account doesn't match the
          // tenant encoded in the access key — catches "wrong account"
          // mistakes that would otherwise silently land the user in
          // the wrong tenant scope.
          ...(tenantInput.trim() ? { account: tenantInput.trim() } : {}),
        }),
      });

      if (!resp.ok) {
        const body = await resp.text().catch(() => "");
        setError(body || "Invalid access key or secret key");
        return;
      }

      const data = await resp.json();
      onLogin(data.display_name || data.email || data.user, data.tenant || "");
    } catch {
      setError("Failed to connect to server");
    } finally {
      setLoading(false);
    }
  };

  const handleSsoLogin = (providerName?: string) => {
    const qs = new URLSearchParams();
    if (providerName) qs.set("provider", providerName);
    if (tenantSso?.tenant) qs.set("tenant", tenantSso.tenant);
    const params = qs.toString();
    window.location.href = `/_console/api/oidc/authorize${params ? `?${params}` : ""}`;
  };

  return (
    <div className="min-h-screen bg-bg flex flex-col items-center justify-center p-6 relative">
      {/* Dotted ground from the artboard. Behind everything, and decorative. */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none opacity-[0.35]"
        style={{
          backgroundImage:
            "radial-gradient(var(--oio-border-strong) 1px, transparent 1px)",
          backgroundSize: "22px 22px",
        }}
      />

      <div className="relative w-full max-w-[400px]">
        <div className="bg-surface border border-border rounded-dialog shadow-sm p-7">
          <img src={mark} alt="" className="h-10 w-10 mb-5" />

          <h1 className="font-display text-[24px] leading-tight font-semibold text-text">
            Sign in to ObjectIO
          </h1>
          {/* The artboard also carries cluster and region here. Nothing
              unauthenticated exposes those today, and inventing a label would
              be worse than omitting it, so the surface name stands alone until
              the server can say. */}
          <p className="text-[12px] text-muted mt-1 mb-6">
            {tenantApp ? "Console" : "Ops console"}
          </p>

          {error && (
            <Banner kind="err" className="mb-4">
              {error}
            </Banner>
          )}

          {tenantApp && (
            <p className="mb-4 text-[12px] text-muted">
              New organisation?{" "}
              <a
                href="/_console/tenant/signup"
                className="text-accent hover:opacity-80 font-medium"
              >
                Create an account
              </a>
            </p>
          )}

          <form onSubmit={handleLogin} className="space-y-3.5">
            {/* Account is only meaningful on the tenant console: the operator
                surface is system-admin only, and the tenant behind a key is
                derived from the key itself. */}
            {tenantApp && (
              <div>
                <Input
                  label="Account"
                  icon={<Building2 size={13} />}
                  value={tenantInput}
                  onChange={(e) => {
                    setTenantInput(e.target.value);
                    setTenantSso(null);
                    setTenantLookupError("");
                  }}
                  onBlur={(e) => lookupTenant(e.target.value)}
                  placeholder="detected from your credentials"
                  error={tenantLookupError || undefined}
                  hint={
                    tenantSso
                      ? `${tenantSso.display_name || tenantSso.tenant}${
                          tenantSso.sso_enabled
                            ? " \u00b7 SSO available"
                            : " \u00b7 password-only"
                        }`
                      : undefined
                  }
                />
              </div>
            )}

            <Input
              label="Access key"
              icon={<User size={13} />}
              value={accessKey}
              onChange={(e) => setAccessKey(e.target.value)}
              placeholder="AKIA…"
              autoFocus
            />

            <Input
              label="Secret key"
              type="password"
              icon={<Lock size={13} />}
              value={secretKey}
              onChange={(e) => setSecretKey(e.target.value)}
              placeholder="Secret access key"
            />

            <div className="flex items-center justify-between pt-0.5">
              <label className="flex items-center gap-2 text-[12px] text-text-2 select-none">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                  className="rounded border-border-strong accent-[var(--oio-accent)]"
                />
                Remember connection
              </label>
              <a
                href="https://objectio.dev/docs/console"
                className="text-[12px] text-accent hover:opacity-80"
              >
                Forgot?
              </a>
            </div>

            <Button
              type="submit"
              variant="primary"
              disabled={loading}
              className="w-full"
            >
              {loading ? "Connecting…" : "Connect"}
            </Button>
          </form>

          {/* SSO. A resolved tenant shows only that tenant's provider, so a
              tenant user cannot land in the wrong account; with no tenant
              scope the surface's own providers are offered. */}
          {tenantSso?.sso_enabled ? (
            <>
              <Divider label={`Or sign in to ${tenantSso.display_name || tenantSso.tenant}`} />
              <Button
                variant="secondary"
                className="w-full"
                icon={<LogIn size={14} />}
                onClick={() => handleSsoLogin(tenantSso.provider_name)}
              >
                Continue with SSO
              </Button>
            </>
          ) : (
            !tenantInput.trim() &&
            oidcEnabled &&
            providers.length > 0 && (
              <>
                <Divider label="Or single sign-on" />
                <div className="space-y-2">
                  {providers.map((p) => (
                    <Button
                      key={p.name}
                      variant="secondary"
                      className="w-full"
                      icon={<LogIn size={14} />}
                      onClick={() => handleSsoLogin(p.name)}
                    >
                      Continue with {p.label}
                    </Button>
                  ))}
                </div>
              </>
            )
          )}
        </div>

        <p className="mt-4 text-center text-[11px] text-muted">
          Need help? See the{" "}
          <a href="https://objectio.dev/docs" className="text-accent hover:opacity-80">
            ObjectIO docs
          </a>
        </p>
      </div>
    </div>
  );
}

/// Mono caps rule used between the credential form and the SSO options.
function Divider({ label }: { label: string }) {
  return (
    <div className="relative my-5">
      <div className="absolute inset-0 flex items-center">
        <div className="w-full border-t border-border" />
      </div>
      <div className="relative flex justify-center">
        <span className="bg-surface px-2 font-mono text-[10px] uppercase tracking-[0.12em] text-faint">
          {label}
        </span>
      </div>
    </div>
  );
}
