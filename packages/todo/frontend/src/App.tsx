import { useEffect, useMemo, useState } from "react";
import { createPasswordCrypto } from "@crypto/password";
import { createWebAuthnCrypto, WebAuthnProvider } from "@crypto/webauthn";
import { TodoList } from "./components/TodoList";
import {
  ShieldCheckIcon,
  KeyIcon,
  ArrowRightIcon,
  UserIcon,
  PowerIcon,
  BoltIcon,
  ChevronDownIcon,
} from "@heroicons/react/24/outline";
import SyncStatusBadge from "./components/SyncStatusBadge";
import Identicon from "./components/Identicon";
import {
  getSupabase,
  signInWithPassword,
  signOut,
  signUpWithPassword,
  signInAnonymously,
  isAnonymousSupported,
} from "./lib/supabase";
import { usePowerSync } from "@powersync/react";
import { useWrappedKey } from "./powersync/keys";
import { ensureDEKWrapped } from "./lib/keyring";
import NewListCard from "./components/NewListCard";
import OpenListCard from "./components/OpenListCard";
import { WASQLiteOpenFactory } from "@powersync/web";

export default function App() {
  const db = usePowerSync();
  const [password, setPassword] = useState("");
  const [ready, setReady] = useState(false);
  const [useWebAuthn, setUseWebAuthn] = useState(false);
  const [email, setEmail] = useState("");
  const [pwd, setPwd] = useState("");
  const [authed, setAuthed] = useState(false);
  const [userId, setUserId] = useState<string | null>(null);
  const [authMenuOpen, setAuthMenuOpen] = useState(false);
  const [anonAvailable, setAnonAvailable] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [passphraseHint, setPassphraseHint] = useState<
    "unknown" | "checking" | "match" | "mismatch" | "no-key" | "not-authed"
  >("unknown");
  const [method, setMethod] = useState<"password" | "webauthn">("password");
  const [webauthnReady, setWebauthnReady] = useState(false);
  // Reactive wrapped key from local DB for current provider
  const { data: wrappedKeyRows } = useWrappedKey(
    userId,
    useWebAuthn ? "webauthn" : "password",
  );
  const wrappedKey = (wrappedKeyRows?.[0] as any) ?? null;
  const [activeKeyId, setActiveKeyId] = useState<string | null>(null);

  // URL state sync: allow back/forward between setup and main screens
  useEffect(() => {
    const p = new URLSearchParams(window.location.search);
    const readyParam = p.get("ready");
    const provParam = p.get("prov");
    const keyParam = p.get("key");
    // Only auto-ready for WebAuthn. For password, require entering passphrase after refresh.
    if (readyParam === "1") {
      if (provParam === "webauthn") setReady(true);
      else setReady(false);
    }
    if (provParam === "webauthn") setUseWebAuthn(true);
    if (keyParam) setActiveKeyId(keyParam);
    const onPop = () => {
      const q = new URLSearchParams(window.location.search);
      const r = q.get("ready") === "1";
      const prov = q.get("prov");
      setUseWebAuthn(prov === "webauthn");
      // Same rule on back/forward: only auto-ready for WebAuthn
      setReady(r && prov === "webauthn");
      setActiveKeyId(q.get("key"));
      setAuthMenuOpen(false);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  function pushMode(
    nextReady: boolean,
    provider: "password" | "webauthn",
    keyId?: string | null,
  ) {
    const q = new URLSearchParams(window.location.search);
    q.set("ready", nextReady ? "1" : "0");
    q.set("prov", provider);
    if (keyId) q.set("key", keyId);
    else q.delete("key");
    window.history.pushState(
      {},
      "",
      `${window.location.pathname}?${q.toString()}`,
    );
  }

  // wrappedKey is reactive via useWrappedKey

  // Simplified hint: rely on presence of a wrapped key for the current provider
  useEffect(() => {
    let cancelled = false;
    (async () => {
      // WebAuthn path: we can't predict until assertion, keep neutral
      if (useWebAuthn) {
        setPassphraseHint("unknown");
        return;
      }
      if (!authed || !userId) {
        setPassphraseHint("not-authed");
        return;
      }
      if (!password) {
        setPassphraseHint("unknown");
        return;
      }
      if (!wrappedKey) {
        setPassphraseHint("no-key");
        return;
      }

      try {
        setPassphraseHint("checking");
        const env = {
          header: {
            v: 1 as const,
            alg: wrappedKey.alg,
            aad: wrappedKey.aad ?? undefined,
            kdf: { saltB64: wrappedKey.kdf_salt_b64 },
          },
          nB64: wrappedKey.nonce_b64,
          cB64: wrappedKey.cipher_b64,
        };
        const provider = createPasswordCrypto({
          password,
          preferWebCrypto: true,
        });
        await provider.decrypt(env, wrappedKey.aad ?? undefined);
        if (!cancelled) setPassphraseHint("match");
      } catch {
        if (!cancelled) setPassphraseHint("mismatch");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [useWebAuthn, authed, userId, wrappedKey, password]);

  const cryptoProvider = useMemo(() => {
    if (!ready) return null;
    if (useWebAuthn) {
      return createWebAuthnCrypto({ keyId: "default" });
    }
    // Prefer WebCrypto PBKDF2 for KDF to avoid heavy Argon2 in UI
    return createPasswordCrypto({ password, preferWebCrypto: true });
  }, [ready, useWebAuthn, password]);


  useEffect(() => {
    (async () => {
      if (!ready) return;
      if (!userId) return;
      try {
        const rows = await db.getAll(
          "SELECT provider, COUNT(*) as cnt FROM e2ee_keys WHERE user_id = ? GROUP BY provider",
          [userId],
        );
        console.debug("[keys] counts for user", userId, rows);
      } catch (e) {
        console.debug("[keys] count query failed", e);
      }
    })();
  }, [ready, userId, db]);


  useEffect(() => {
    const sb = getSupabase();

    if (!sb) return;
    setAnonAvailable(isAnonymousSupported());
    // initial fetch — prefer cached session (no network) for snappy UI
    sb.auth.getSession().then(({ data }) => {
      setAuthed(!!data.session);
      setUserId(data.session?.user?.id ?? null);
    });
    // subscribe to changes
    const { data: sub } = sb.auth.onAuthStateChange((_e, session) => {
      setAuthed(!!session);
      setUserId(session?.user?.id ?? null);
    });
    return () => {
      sub.subscription.unsubscribe();
    };
  }, []);

  function shortId(id: string) {
    if (id.length <= 10) return id;
    return id.slice(0, 6) + "…" + id.slice(-4);
  }

  // Connection status surfaces via SyncStatusBadge; explicit connect not required here.

  if (!ready || !cryptoProvider) {
    return (
      <div className="min-h-screen bg-gradient-to-b from-white to-gray-50 dark:from-gray-900 dark:to-gray-900">
        <div className="max-w-2xl mx-auto px-4 py-10">
          <header className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <span className="h-9 w-9 rounded-lg bg-blue-600 text-white flex items-center justify-center shadow-sm">
                <ShieldCheckIcon className="h-5 w-5" />
              </span>
              <div className="leading-tight">
                <h1 className="text-xl sm:text-2xl font-semibold tracking-tight">
                  Encrypted TODO app
                </h1>
                <p className="muted -mt-0.5">End‑to‑end encrypted</p>
              </div>
            </div>
            <div className="relative">
              {userId ? (
                <button
                  type="button"
                  className="inline-flex items-center gap-2 px-2 py-1 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800"
                  onClick={() => setAuthMenuOpen((v) => !v)}
                >
                  <Identicon seed={userId} size={22} />
                  <ChevronDownIcon className="h-4 w-4" />
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    className="btn-secondary-sm"
                    onClick={() => setAuthMenuOpen((v) => !v)}
                  >
                    <UserIcon className="h-4 w-4" /> Sign In
                  </button>
                  <button
                    type="button"
                    className="btn-secondary-sm"
                    onClick={async () => {
                      setAuthError(null);
                      try {
                        await signInAnonymously();
                      } catch (e: any) {
                        setAuthError(e?.message ?? String(e));
                      }
                    }}
                    disabled={!anonAvailable}
                  >
                    <UserIcon className="h-4 w-4" /> Guest
                  </button>
                </div>
              )}
              <div className="absolute -left-28 top-0">
                <SyncStatusBadge />
              </div>
              {authMenuOpen && !userId && (
                <div className="absolute right-0 mt-2 w-72 rounded-md border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-lg p-3 z-10">
                  <div className="flex flex-col gap-2">
                    <input
                      className="input-sm"
                      placeholder="Email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                    <input
                      className="input-sm"
                      type="password"
                      autoComplete="current-password"
                      placeholder="Password"
                      value={pwd}
                      onChange={(e) => setPwd(e.target.value)}
                    />
                    <div className="flex gap-2 justify-end">
                      <button
                        type="button"
                        className="btn-secondary-sm"
                        onClick={async () => {
                          setAuthError(null);
                          try {
                            await signInWithPassword(email, pwd);
                            setAuthMenuOpen(false);
                          } catch (e: any) {
                            setAuthError(e?.message ?? String(e));
                          }
                        }}
                        disabled={!email || !pwd}
                      >
                        Sign In
                      </button>
                      <button
                        type="button"
                        className="btn-secondary-sm"
                        onClick={async () => {
                          setAuthError(null);
                          try {
                            await signUpWithPassword(email, pwd);
                            setAuthMenuOpen(false);
                          } catch (e: any) {
                            setAuthError(e?.message ?? String(e));
                          }
                        }}
                        disabled={!email || !pwd}
                      >
                        Sign Up
                      </button>
                    </div>
                  </div>
                </div>
              )}
              {authMenuOpen && userId && (
                <div className="absolute right-0 mt-2 w-48 rounded-md border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-lg p-2 z-10">
                  <button
                    type="button"
                    className="w-full text-left px-2 py-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                    onClick={() => {
                      setAuthMenuOpen(false);
                      signOut();
                    }}
                  >
                    <PowerIcon className="h-4 w-4 inline mr-1" /> Sign Out
                  </button>
                </div>
              )}
            </div>
          </header>
          {authError && (
            <div className="text-xs text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 rounded-md p-2 mb-3">
              {authError}
            </div>
          )}

          {/* Setup screen split into: Open existing + Create new */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
            <NewListCard
              onCreate={(method, secret, listName) => {
                // Create a stable key id for the list
                const slug = slugify(listName || cryptoRandom());
                const keyId = userId
                  ? `${userId}:${method}:${slug}`
                  : `${method}:${slug}`;
                setActiveKeyId(keyId);
                (async () => {
                  // Pre-create wrapped DEK only for password lists
                  // WebAuthn deriveSecret triggers navigator.credentials.get(); avoid concurrent prompts.
                  try {
                    if (userId && method === 'password') {
                      const wrapper = createPasswordCrypto({
                        password: secret || '',
                        preferWebCrypto: true,
                      });
                      await ensureDEKWrapped(db, userId, method, wrapper, keyId);
                    }
                  } catch (e) {
                    console.warn('Pre-create wrapped DEK failed (will retry on open):', e);
                  }
                  if (method === "webauthn") {
                    setUseWebAuthn(true);
                    setReady(true);
                    pushMode(true, "webauthn", keyId);
                  } else {
                    setUseWebAuthn(false);
                    setPassword(secret || "");
                    setReady(true);
                    pushMode(true, "password", keyId);
                  }
                })();
              }}
            />
            <OpenListCard
              userId={userId}
              authed={authed}
              onOpen={(keyId, provider, secret) => {
                setActiveKeyId(keyId);
                if (provider === "webauthn") {
                  setUseWebAuthn(true);
                  setReady(true);
                  pushMode(true, "webauthn", keyId);
                } else {
                  setUseWebAuthn(false);
                  setPassword(secret || "");
                  setReady(true);
                  pushMode(true, "password", keyId);
                }
              }}
            />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-b from-white to-gray-50 dark:from-gray-900 dark:to-gray-900">
      <div className="max-w-2xl mx-auto px-4 py-8">
        <header className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-3">
            <span className="h-9 w-9 rounded-lg bg-blue-600 text-white flex items-center justify-center shadow-sm">
              <ShieldCheckIcon className="h-5 w-5" />
            </span>
            <h1 className="text-xl sm:text-2xl font-semibold tracking-tight">
              Encrypted Tasks
            </h1>
          </div>
          <div className="flex items-center gap-3 relative">
            <SyncStatusBadge />
            {userId ? (
              <button
                type="button"
                className="inline-flex items-center gap-2 px-2 py-1 rounded-md hover:bg-gray-100 dark:hover:bg-gray-800"
                onClick={() => setAuthMenuOpen((v) => !v)}
              >
                <Identicon seed={userId} size={22} />
                <ChevronDownIcon className="h-4 w-4" />
              </button>
            ) : (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="btn-secondary-sm"
                  onClick={() => setAuthMenuOpen((v) => !v)}
                >
                  <UserIcon className="h-4 w-4" /> Sign In
                </button>
                <button
                  type="button"
                  className="btn-secondary-sm"
                  onClick={async () => {
                    setAuthError(null);
                    try {
                      await signInAnonymously();
                    } catch (e: any) {
                      setAuthError(e?.message ?? String(e));
                    }
                  }}
                  disabled={!anonAvailable}
                >
                  <UserIcon className="h-4 w-4" /> Guest
                </button>
              </div>
            )}
            {authMenuOpen && !userId && (
              <div className="absolute right-0 top-10 w-72 rounded-md border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-lg p-3 z-10">
                <div className="flex flex-col gap-2">
                  <input
                    className="input-sm"
                    placeholder="Email"
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                  <input
                    className="input-sm"
                    type="password"
                    autoComplete="current-password"
                    placeholder="Password"
                    value={pwd}
                    onChange={(e) => setPwd(e.target.value)}
                  />
                  <div className="flex gap-2 justify-end">
                    <button
                      type="button"
                      className="btn-secondary-sm"
                      onClick={async () => {
                        setAuthError(null);
                        try {
                          await signInWithPassword(email, pwd);
                          setAuthMenuOpen(false);
                        } catch (e: any) {
                          setAuthError(e?.message ?? String(e));
                        }
                      }}
                      disabled={!email || !pwd}
                    >
                      Sign In
                    </button>
                    <button
                      type="button"
                      className="btn-secondary-sm"
                      onClick={async () => {
                        setAuthError(null);
                        try {
                          await signUpWithPassword(email, pwd);
                          setAuthMenuOpen(false);
                        } catch (e: any) {
                          setAuthError(e?.message ?? String(e));
                        }
                      }}
                      disabled={!email || !pwd}
                    >
                      Sign Up
                    </button>
                  </div>
                </div>
              </div>
            )}
            {authMenuOpen && userId && (
              <div className="absolute right-0 top-10 w-48 rounded-md border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 shadow-lg p-2 z-10">
                <div className="px-2 py-1 text-xs text-gray-600 dark:text-gray-300">
                  {shortId(userId)}
                </div>
                <button
                  type="button"
                  className="w-full text-left px-2 py-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                  onClick={() => {
                    setAuthMenuOpen(false);
                    signOut();
                  }}
                >
                  <PowerIcon className="h-4 w-4 inline mr-1" /> Sign Out
                </button>
              </div>
            )}
          </div>
        </header>

        <TodoList
          crypto={cryptoProvider}
          providerKind={useWebAuthn ? "webauthn" : "password"}
          activeKeyId={activeKeyId}
          onLogCipher={(env) => {
            // demo: show compact envelope size
            const size = env.cB64.length;
            console.info(
              "cipher env header.alg",
              env.header.alg,
              "ciphertext.size",
              size,
            );
          }}
        />

        <footer className="mt-10 muted">
          <p>
            Raw SQLite tables store only metadata (
            <code className="mx-1">user_id</code>,{" "}
            <code className="mx-1">bucket_id</code>) and encrypted envelopes.
          </p>
        </footer>
      </div>
    </div>
  );
}

function slugify(s: string): string {
  return (
    s
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 32) || "list"
  );
}

function cryptoRandom(): string {
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
