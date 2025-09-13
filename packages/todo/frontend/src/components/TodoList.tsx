import { useEffect, useMemo, useRef, useState } from "react";
import type { CryptoProvider, CipherEnvelope } from "@crypto/interface";
import { utf8, columnsToEnvelope } from "@crypto/interface";
import { usePowerSync, useQuery, useStatus } from "@powersync/react";
import LoadingSpinner from "./LoadingSpinner";
import {
  SELECT_BY_USER_SQL,
  SELECT_BY_USER_AND_BUCKET_SQL,
  SELECT_BY_USER_OPTIONAL_BUCKET_SQL,
  INSERT_SQL,
  UPDATE_SQL,
  DELETE_SQL,
} from "../powersync/todosSql";
import { ensureDEKWrapped } from "../lib/keyring";
import { DataCrypto } from "../lib/dataCrypto";
import { getCurrentUserId } from "../lib/supabase";
import {
  PlusIcon,
  ArrowPathIcon,
  TrashIcon,
} from "@heroicons/react/24/outline";

type Todo = {
  id: string;
  text: string;
  completed: boolean;
  env: CipherEnvelope; // encrypted envelope stored remotely
  synced?: boolean; // visual indicator
};

export function TodoList({
  crypto,
  onLogCipher,
  providerKind,
  activeKeyId,
}: {
  crypto: CryptoProvider;
  onLogCipher?: (env: CipherEnvelope) => void;
  providerKind: "password" | "webauthn";
  activeKeyId: string | null;
}) {
  const [items, setItems] = useState<Todo[]>([]);
  const db = usePowerSync();
  const status = useStatus();
  const [text, setText] = useState("");
  const [bucketId, setBucketId] = useState<string>("");
  const aad = useMemo(() => "todo-v1", []);
  const [userId, setUserId] = useState<string | null>(null);
  const [dataCrypto, setDataCrypto] = useState<DataCrypto | null>(null);

  // Managed 'todos' table is declared in schema; no manual CREATE needed

  // Resolve current user and prepare DEK (guard against duplicate/in-flight init)
  const initInFlight = useRef(false);
  const dekReadyRef = useRef(false);
  useEffect(() => {
    (async () => {
      const uid = await getCurrentUserId(true);
      setUserId(uid);
      if (!uid) {
        console.debug("No user, skipping DEK");
        return;
      }
      if (dekReadyRef.current || initInFlight.current) return;
      initInFlight.current = true;
      try {
        const rows = await db.getAll(
          "SELECT provider, COUNT(*) as cnt FROM e2ee_keys WHERE user_id = ? GROUP BY provider",
          [uid],
        );
        console.debug("[keys] (TodoList) counts for user", uid, rows);

        const dek = await ensureDEKWrapped(
          db,
          uid,
          providerKind,
          crypto,
          activeKeyId ?? undefined,
        );
        setDataCrypto(new DataCrypto(dek));
        dekReadyRef.current = true;
      } catch (e) {
        console.error("Failed to prepare DEK, disabling data encryption", e);
        setDataCrypto(null);
      } finally {
        initInFlight.current = false;
      }
    })();
  }, [db, crypto, providerKind, activeKeyId]);

  // When activeKeyId changes, lock bucketId to it
  useEffect(() => {
    if (activeKeyId) setBucketId(activeKeyId);
  }, [activeKeyId]);

  // Live query for this user's rows
  const {
    data: rows,
    isLoading: rowsLoading,
    isFetching,
  } = useQuery(
    SELECT_BY_USER_OPTIONAL_BUCKET_SQL,
    [userId ?? "", bucketId || ""],
    { throttleMs: 300 },
  );

  // Log watch state transitions
  useEffect(() => {
    if (rowsLoading) console.debug("[perf] load: initial loading…");
  }, [rowsLoading]);
  useEffect(() => {
    if (isFetching) console.debug("[perf] load: fetching…");
  }, [isFetching]);

  const logKeyRef = useRef<string>("");

  // Decrypt whenever rows change; preserve optimistic (unsynced) items during refresh
  useEffect(() => {
    (async () => {
      if (!rows) return;
      // Avoid clearing the list during in-flight refresh when rows are transiently empty
      if (isFetching && (rows as any[]).length === 0) return;
      const t0 = performance.now();
      const serverItems: Todo[] = [];
      let ok = 0,
        fail = 0;
      for (const r of rows as any[]) {
        const env: CipherEnvelope = columnsToEnvelope({
          alg: r.alg,
          aad: r.aad ?? null,
          nonce_b64: r.nonce_b64,
          cipher_b64: r.cipher_b64,
          kdf_salt_b64: r.kdf_salt_b64,
        });
        try {
          const isRaw = env.header.alg.includes("/raw");
          let plain: Uint8Array;
          if (isRaw && !dataCrypto) {
            // List is locked (no DEK) — skip silently (do not count as failure)
            continue;
          }
          if (isRaw) {
            plain = await dataCrypto!.decrypt(env, r.aad ?? undefined);
          } else {
            plain = await crypto.decrypt(env, r.aad ?? undefined);
          }
          const decoded = new TextDecoder().decode(plain);
          let text = decoded;
          let completed = false;
          try {
            const obj = JSON.parse(decoded) as {
              text?: string;
              completed?: boolean;
            };
            if (typeof obj?.text === "string") text = obj.text;
            if (typeof obj?.completed === "boolean") completed = obj.completed;
          } catch {}
          serverItems.push({ id: r.id, text, completed, env, synced: true });
          ok++;
        } catch (e) {
          console.error("Failed to decrypt todo item", r.id, e);
          fail++;
        }
      }
      // Preserve optimistic (unsynced) items not yet present in server rows
      const serverIds = new Set(serverItems.map((t) => t.id));
      setItems((prev) => {
        const optimistic = prev.filter(
          (t) => !t.synced && !serverIds.has(t.id),
        );
        return [...optimistic, ...serverItems];
      });
      const t1 = performance.now();
      // Throttle noisy logs: only when not fetching and counts change
      const key = `${ok}-${fail}-${(rows as any[]).length}-${isFetching ? 1 : 0}`;
      if (!isFetching && key !== logKeyRef.current) {
        console.debug(
          "[perf] load: decrypted",
          ok,
          "rows",
          fail ? `(failed ${fail})` : "",
          "in",
          Math.round(t1 - t0),
          "ms",
        );
        logKeyRef.current = key;
      }
    })();
  }, [rows, crypto, dataCrypto, isFetching]);

  async function addTodo() {
    if (!text.trim()) return;
    if (!dataCrypto) {
      console.warn("DEK not ready; cannot add todo.");
      return;
    }
    const perf0 = performance.now();
    console.debug("[perf] addTodo: start", {
      hasUser: !!userId,
      textLen: text.trim().length,
    });
    // Encrypt JSON payload to include completed flag
    const payload = JSON.stringify({ text: text.trim(), completed: false });
    const encStart = performance.now();
    const env = await dataCrypto.encrypt(utf8(payload), aad);
    const encEnd = performance.now();
    console.debug(
      "[perf] addTodo: encrypted",
      Math.round(encEnd - encStart),
      "ms",
    );
    const id = cryptoRandomId();
    onLogCipher?.(env);
    const localStart = performance.now();
    setItems((prev) => [
      { id, text: text.trim(), completed: false, env, synced: false },
      ...prev,
    ]);
    setText("");
    const localEnd = performance.now();
    console.debug(
      "[perf] addTodo: local state update",
      Math.round(localEnd - localStart),
      "ms",
    );
    // Persist to PowerSync raw table if authenticated
    if (userId) {
      const now = new Date().toISOString();
      const dbStart = performance.now();
      await db.execute(INSERT_SQL, [
        id,
        userId,
        bucketId || null,
        env.header.alg,
        aad ?? null,
        env.nB64,
        env.cB64,
        env.header.kdf.saltB64 ?? "",
        now,
        now,
      ]);
      const dbEnd = performance.now();
      console.debug(
        "[perf] addTodo: db.insert",
        Math.round(dbEnd - dbStart),
        "ms",
      );
      setItems((prev) =>
        prev.map((t) => (t.id === id ? { ...t, synced: true } : t)),
      );
    }
    const perfEnd = performance.now();
    console.debug("[perf] addTodo: total", Math.round(perfEnd - perf0), "ms");
  }

  async function toggleCompleted(id: string) {
    const t = items.find((x) => x.id === id);
    if (!t) return;
    if (!dataCrypto) {
      console.warn("DEK not ready; cannot toggle.");
      return;
    }
    const nextCompleted = !t.completed;
    const payload = JSON.stringify({ text: t.text, completed: nextCompleted });
    const env = await dataCrypto.encrypt(utf8(payload), aad);
    setItems((prev) =>
      prev.map((x) =>
        x.id === id
          ? { ...x, completed: nextCompleted, env, synced: false }
          : x,
      ),
    );
    try {
      if (userId) {
        const now = new Date().toISOString();
        await db.execute(UPDATE_SQL, [
          env.header.alg,
          aad ?? null,
          env.nB64,
          env.cB64,
          env.header.kdf.saltB64 ?? "",
          now,
          id,
          userId,
        ]);
        setItems((prev) =>
          prev.map((x) => (x.id === id ? { ...x, synced: true } : x)),
        );
      }
    } catch {}
  }

  async function removeTodo(id: string) {
    setItems((prev) => prev.filter((x) => x.id !== id));
    try {
      if (userId) {
        await db.execute(DELETE_SQL, [id, userId]);
      }
    } catch {}
  }

  // Removed helper wrappers; we call SQL directly via usePowerSync

  async function refreshFromServer() {
    if (!userId) return;
    try {
      const rows = (await db.getAll(SELECT_BY_USER_SQL, [userId])) as any[];
      const decrypted: Todo[] = [];
      for (const r of rows) {
        const env: CipherEnvelope = columnsToEnvelope({
          alg: r.alg,
          aad: r.aad ?? null,
          nonce_b64: r.nonce_b64,
          cipher_b64: r.cipher_b64,
          kdf_salt_b64: r.kdf_salt_b64,
        });
        try {
          const useData = env.header.alg.includes("/raw") && dataCrypto;
          const plain = useData
            ? await dataCrypto!.decrypt(env, r.aad ?? undefined)
            : await crypto.decrypt(env, r.aad ?? undefined);
          const decoded = new TextDecoder().decode(plain);
          let text = decoded;
          let completed = false;
          try {
            const obj = JSON.parse(decoded) as {
              text?: string;
              completed?: boolean;
            };
            if (typeof obj?.text === "string") text = obj.text;
            if (typeof obj?.completed === "boolean") completed = obj.completed;
          } catch {}
          decrypted.push({ id: r.id, text, completed, env, synced: true });
        } catch {}
      }
      setItems(decrypted);
    } catch {}
  }

  return (
    <div className="card">
      <div className="flex gap-2 mb-4">
        <input
          className="input flex-1"
          placeholder="Add a task"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && addTodo()}
        />
        <button
          className="btn"
          onClick={addTodo}
          disabled={!text.trim() || !userId || !dataCrypto}
        >
          <PlusIcon className="h-4 w-4" /> Add
        </button>
      </div>
      <div className="flex items-center gap-3 mb-3 text-xs text-gray-600 dark:text-gray-400">
        <span>
          {status.connecting
            ? "Connecting…"
            : status.connected
              ? status.dataFlowStatus?.downloading ||
                status.dataFlowStatus?.uploading
                ? "Syncing…"
                : "Synced"
              : "Offline"}
        </span>
      </div>

      <div className="flex items-center gap-2 mb-5">
        <input
          className="input flex-1"
          placeholder="Optional bucket id (leaked)"
          value={bucketId}
          onChange={(e) => setBucketId(e.target.value)}
        />
        <button
          className="btn-secondary"
          onClick={refreshFromServer}
          disabled={!userId}
        >
          <ArrowPathIcon className="h-4 w-4" /> Refresh
        </button>
      </div>
      {!userId && (
        <div className="rounded-md border border-amber-300 bg-amber-50 text-amber-800 p-2 text-sm mb-5">
          Please sign in or continue as guest to create and sync todos.
        </div>
      )}
      {userId && !dataCrypto && (
        <div className="rounded-md border border-amber-300 bg-amber-50 text-amber-800 p-2 text-sm mb-5">
          Your encryption key is locked or not set. Choose a passphrase or
          passkey first.
        </div>
      )}
      {rowsLoading && items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 dark:border-gray-700 p-8 text-center">
          <div className="flex items-center justify-center gap-2 text-gray-600 dark:text-gray-300">
            <LoadingSpinner size={16} />
            <span>Loading your tasks…</span>
          </div>
        </div>
      ) : items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-gray-300 dark:border-gray-700 p-8 text-center">
          <p className="muted">
            No tasks yet. Add your first encrypted task above.
          </p>
        </div>
      ) : (
        <ul className="space-y-2 relative">
          {isFetching && (
            <div className="absolute -top-7 right-0 text-xs text-gray-500 inline-flex items-center gap-2">
              <LoadingSpinner size={12} />
              <span>Refreshing…</span>
            </div>
          )}
          {items.map((t) => (
            <li
              key={t.id}
              className="p-3 rounded-md border border-gray-200 dark:border-gray-700"
            >
              <div className="flex items-center justify-between gap-3">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    className="size-4"
                    checked={t.completed}
                    onChange={() => toggleCompleted(t.id)}
                  />
                  <span
                    className={t.completed ? "line-through opacity-70" : ""}
                  >
                    {t.text}
                  </span>
                </label>
                <div className="flex items-center gap-3">
                  <span
                    className={
                      "text-xs " +
                      (t.synced ? "text-green-600" : "text-gray-500")
                    }
                  >
                    {t.synced ? "synced" : "local"}
                  </span>
                  <span className="text-xs text-gray-500">
                    enc {t.env.cB64.length}B
                  </span>
                  <button
                    className="btn-secondary"
                    onClick={() => removeTodo(t.id)}
                  >
                    <TrashIcon className="h-4 w-4" /> Delete
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function cryptoRandomId() {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
