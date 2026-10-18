import { useEffect, useState } from "react";
import { Building2, LogIn, ArrowLeft } from "lucide-react";
import wordmark from "../assets/brand/wordmark-light.svg";

interface Provider {
  name: string;
  label: string;
}

/// Self-registration for a new organisation.
///
/// Distinct from the tenant sign-in page on purpose. Sign-in asks for an
/// account name and then offers that tenant's SSO — which cannot work here,
/// because the whole point is that the organisation does not have an account
/// yet and so has nothing to look up. This page offers the providers that
/// federate many organisations; completing one registers the tenant from the
/// upstream tenant id in the resulting token.
export default function Signup() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loading, setLoading] = useState(true);
  // Read straight from the URL at mount. A failed callback redirects back
  // here with ?error=..., and taking it as initial state rather than setting
  // it from an effect keeps the first render correct.
  const [error] = useState(() =>
    new URLSearchParams(window.location.search).get("error") ?? ""
  );

  useEffect(() => {
    // Tidying the address bar is an external-system update, which is what an
    // effect is for.
    if (error) {
      window.history.replaceState({}, "", window.location.pathname);
    }
    fetch("/_console/api/oidc/enabled?purpose=signup")
      .then((r) => r.json())
      .then((d) => setProviders(d.providers || []))
      .catch(() => setProviders([]))
      .finally(() => setLoading(false));
    // Mount-only. `error` is fixed at first render by the initialiser above,
    // so it cannot change and does not belong in the dependency list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const start = (provider: string) => {
    window.location.assign(
      `/_console/api/oidc/authorize?provider=${encodeURIComponent(provider)}`
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br bg-bg flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        <div className="flex justify-center mb-8">
          <img src={wordmark} alt="ObjectIO" className="h-8" />
        </div>

        <div className="bg-surface rounded-2xl border border-border shadow-sm p-7">
          <div className="flex items-center gap-2 mb-1">
            <Building2 size={16} className="text-faint" />
            <h1 className="font-display text-[20px] leading-tight font-semibold text-text">
              Create an organisation account
            </h1>
          </div>
          <p className="text-[12px] text-muted mb-6">
            Sign in with your work account. Your organisation gets its own
            account, and you become its first member — there is nothing to fill
            in and nobody to wait for.
          </p>

          {error && (
            <div className="mb-4 rounded-lg border border-err/25 bg-err-soft px-3 py-2">
              <p className="text-[12px] text-err break-words">{error}</p>
            </div>
          )}

          {loading ? (
            <p className="text-[12px] text-faint">Loading…</p>
          ) : providers.length === 0 ? (
            /* Nothing to offer means no multi-tenant provider is configured.
               Say which setting is missing rather than showing an empty page. */
            <div className="rounded-lg border border-warn/25 bg-warn-soft px-3 py-2.5">
              <p className="text-[12px] text-warn font-medium">
                Registration is not open
              </p>
              <p className="text-[11px] text-warn mt-0.5">
                No identity provider on this server is configured for
                multi-tenant sign-up. An operator enables it by setting a
                provider's Tenancy to &ldquo;multi-tenant&rdquo; in the admin
                console.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {providers.map((p) => (
                <button
                  key={p.name}
                  onClick={() => start(p.name)}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2.5 bg-surface-2 border border-border text-text rounded-lg text-[13px] font-medium hover:bg-surface-2"
                >
                  <LogIn size={14} />
                  Continue with {p.label}
                </button>
              ))}
            </div>
          )}

          <div className="mt-6 pt-4 border-t border-border">
            <a
              href="/_console/tenant/"
              className="inline-flex items-center gap-1.5 text-[12px] text-muted hover:text-text-2"
            >
              <ArrowLeft size={12} />
              Already have an account? Sign in
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
