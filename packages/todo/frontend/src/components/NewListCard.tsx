import { KeyIcon, ArrowRightIcon } from "@heroicons/react/24/outline";
import { WebAuthnProvider } from "@crypto/webauthn";
import React, { useState } from "react";

export function NewListCard({
  onCreate,
}: {
  onCreate: (
    method: "password" | "webauthn",
    secret: string | undefined,
    listName: string,
  ) => void;
}) {
  const [password, setPassword] = useState("");
  const [webauthnReady, setWebauthnReady] = useState(false);
  const [method, setMethod] = useState<"password" | "webauthn">("password");
  const [listName, setListName] = useState("");
  const [waError, setWaError] = useState<string | null>(null);

  return (
    <div className="card flex flex-col gap-3">
      <div>
        <h2 className="text-lg font-medium">Create TODO list</h2>
        <p className="muted">
          Choose a passphrase or set up a passkey. Your data encrypts locally.
        </p>
      </div>
      <div className="flex flex-col gap-2">
        <label className="text-xs font-medium">List name</label>
        <input
          className="input-sm"
          type="text"
          placeholder="e.g., Personal, Work"
          value={listName}
          onChange={(e) => setListName(e.target.value)}
        />
      </div>
      <div className="flex flex-col gap-2">
        <label className="text-xs font-medium">Passphrase</label>
        <div className="flex gap-2">
          <input
            className="input-sm flex-1"
            name="new-passphrase"
            type="password"
            placeholder="Create a passphrase"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setMethod("password");
            }}
            autoComplete="new-password"
            data-lpignore="true"
            data-1p-ignore="true"
            spellCheck={false}
            inputMode="text"
          />
          <button
            type="button"
            className={"btn-secondary-sm"}
            onClick={async () => {
              try {
                setWaError(null);
                const prov = new WebAuthnProvider({ keyId: "default" });
                await prov.register("User");
                setMethod("webauthn");
                let ok = false;
                try {
                  await prov.encrypt(new Uint8Array([0]), "e2ee-probe");
                  ok = true;
                } catch (e){
                  console.error(e)
                  ok = false;
                }
                if (ok) {
                  setWebauthnReady(true);
                } else {
                  setWebauthnReady(false);
                  setWaError(
                    "This passkey cannot derive a secret (PRF/hmac-secret unsupported). Try another device or use a passphrase.",
                  );
                }
              } catch (e: any) {
                setWaError(e?.message ?? String(e));
              }
            }}
          >
            <KeyIcon className="h-4 w-4" /> Set up passkey
          </button>
        </div>
      </div>
      {method === "webauthn" && waError && (
        <div className="text-xs text-amber-700 dark:text-amber-400">{waError}</div>
      )}
      <div className="flex justify-end mt-2">
        <button
          type="button"
          className="btn-sm"
          onClick={() => {
            if (method === "webauthn") {
              if (!webauthnReady) return;
              onCreate("webauthn", undefined, listName.trim());
            } else {
              if (!password) return;
              onCreate("password", password, listName.trim());
            }
          }}
          disabled={
            (method === "webauthn" ? !webauthnReady : !password) ||
            !listName.trim()
          }
          title={
            !listName.trim()
              ? "Enter a list name"
              : method === "webauthn"
                ? webauthnReady
                  ? ""
                  : "Set up a passkey first"
                : !password
                  ? "Enter a passphrase"
                  : ""
          }
        >
          Create <ArrowRightIcon className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

export default NewListCard;
