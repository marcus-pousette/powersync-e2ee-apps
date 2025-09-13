import React, { useMemo, useState, useEffect } from "react";
import { useQuery } from "@powersync/react";
import { createPasswordCrypto } from "@crypto/password";
import { WebAuthnProvider } from "@crypto/webauthn";

type KeyRow = {
  id: string;
  provider: "password" | "webauthn";
  created_at: string;
  alg: string;
  aad?: string | null;
  nonce_b64: string;
  cipher_b64: string;
  kdf_salt_b64: string;
};

type Hint = "unknown" | "checking" | "match" | "mismatch" | "not-authed";

export function OpenListCard({
  userId,
  authed,
  onOpen,
}: {
  userId: string | null;
  authed: boolean;
  onOpen: (
    keyId: string,
    provider: "password" | "webauthn",
    secret?: string,
  ) => void;
}) {
  const { data } = useQuery<KeyRow>(
    "SELECT id, provider, created_at, alg, aad, nonce_b64, cipher_b64, kdf_salt_b64 FROM e2ee_keys WHERE user_id = ? ORDER BY created_at DESC",
    [userId ?? ""],
    { throttleMs: 250 },
  );

  const [stableKeys, setStableKeys] = useState<KeyRow[]>([]);
  useEffect(() => {
    // Reset cache when switching users
    if (!userId) setStableKeys([]);
  }, [userId]);
  useEffect(() => {
    if (Array.isArray(data) && (data as any[]).length > 0) {
      setStableKeys(data as any[] as KeyRow[]);
    }
  }, [data]);
  const keys =
    Array.isArray(data) && (data as any[]).length > 0
      ? (data as any[] as KeyRow[])
      : stableKeys;
  const [passwords, setPasswords] = useState<Record<string, string>>({});
  const [hints, setHints] = useState<Record<string, Hint>>({});

  // Compute hints only for password-rows where a passphrase is entered
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const pending: Record<string, Hint> = {};
      for (const k of keys) {
        if (k.provider !== "password") continue;
        const pw = passwords[k.id] || "";
        if (!authed || !userId) {
          pending[k.id] = "not-authed";
          continue;
        }
        if (!pw) {
          pending[k.id] = "unknown";
          continue;
        }
        pending[k.id] = "checking";
        try {
          const env = {
            header: {
              v: 1 as const,
              alg: k.alg,
              aad: k.aad ?? undefined,
              kdf: { saltB64: k.kdf_salt_b64 },
            },
            nB64: k.nonce_b64,
            cB64: k.cipher_b64,
          };
          const provider = createPasswordCrypto({
            password: pw,
            preferWebCrypto: true,
          });
          await provider.decrypt(env, k.aad ?? undefined);
          if (!cancelled) pending[k.id] = "match";
        } catch {
          if (!cancelled) pending[k.id] = "mismatch";
        }
      }
      if (!cancelled) setHints((prev) => ({ ...prev, ...pending }));
    })();
    return () => {
      cancelled = true;
    };
  }, [keys, passwords, authed, userId]);

  return (
    <div className="card flex flex-col gap-3">
      <div>
        <h2 className="text-lg font-medium">Open a TODO list</h2>
        <p className="muted">
          Select a list you created before and enter its passphrase or use your
          passkey.
        </p>
      </div>
      {keys.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 dark:border-gray-700 p-6 text-center">
          <p className="muted">No lists yet. Create your first one.</p>
        </div>
      ) : (
        <ul className="space-y-3">
          {keys.map((k) => {
            const isPassword = k.provider === "password";
            const hint = hints[k.id] ?? "unknown";
            return (
              <li
                key={k.id}
                className="p-3 rounded-md border border-gray-200 dark:border-gray-700"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="flex flex-col">
                    <div className="font-medium">
                      {labelFromId(k.id)}{" "}
                      <span className="muted">({k.provider})</span>
                    </div>
                    <div className="text-xs muted">
                      {new Date(k.created_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {isPassword ? (
                      <>
                        <input
                          className="input-sm"
                          type="password"
                          placeholder="Passphrase"
                          value={passwords[k.id] || ""}
                          onChange={(e) =>
                            setPasswords((p) => ({
                              ...p,
                              [k.id]: e.target.value,
                            }))
                          }
                          autoComplete="current-password"
                        />
                        <button
                          className="btn-secondary-sm"
                          onClick={() =>
                            onOpen(k.id, "password", passwords[k.id])
                          }
                          disabled={!passwords[k.id]}
                        >
                          Open
                        </button>
                      </>
                    ) : (
                      <button
                        className="btn-secondary-sm"
                        onClick={async () => {
                          try {
                            const prov = new WebAuthnProvider({ keyId: "default" });
                            try {
                              await prov.encrypt(new Uint8Array([0]), "e2ee-probe");
                            } catch {
                              alert(
                                "This passkey cannot derive a secret on this device. Try another device or use a passphrase.",
                              );
                              return;
                            }
                            onOpen(k.id, "webauthn");
                          } catch (e: any) {
                            alert(
                              e?.message ??
                                "No passkey registered on this device for this app.",
                            );
                          }
                        }}
                      >
                        Open
                      </button>
                    )}
                  </div>
                </div>
                {isPassword && (
                  <div className="mt-2 text-xs">
                    {hint === "checking" ? (
                      <span className="inline-flex items-center gap-2 text-gray-600 dark:text-gray-300">
                        <span className="inline-block animate-spin h-3 w-3 rounded-full border-2 border-gray-400 border-t-transparent"></span>
                        Checking passphrase…
                      </span>
                    ) : hint === "match" ? (
                      <span className="text-green-700 dark:text-green-400">
                        Passphrase looks correct for this list.
                      </span>
                    ) : hint === "mismatch" ? (
                      <span className="text-amber-700 dark:text-amber-400">
                        This passphrase doesn’t match this list.
                      </span>
                    ) : !authed ? (
                      <span className="muted">
                        Sign in to check against your saved key.
                      </span>
                    ) : (
                      <span className="muted">
                        Enter a passphrase to check.
                      </span>
                    )}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function labelFromId(id: string): string {
  const parts = id.split(":");
  return parts[2] || id;
}

export default OpenListCard;
