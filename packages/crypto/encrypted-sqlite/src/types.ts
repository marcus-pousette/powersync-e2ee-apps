import type { AbstractPowerSyncDatabase } from "@powersync/web";
import type { CipherEnvelope, CryptoProvider, EncryptedColumns} from "@crypto/interface";


/** Mirror column definition (SQLite flavor) */
export type MirrorColumnDef = {
  name: string;           // e.g., "text", "completed", "priority"
  type: string;           // e.g., "TEXT", "INTEGER", "REAL", "BLOB", "NUMERIC"
  notNull?: boolean;
  defaultExpr?: string;   // raw SQL default expression (e.g., "0", "'pending'")
};

/** Values mapped into the mirror (by parsePlain) */
export type MirrorValues = Record<string, any>;

/** How to parse decrypted bytes into mirror column values */
export type ParsePlainFn = (args: {
  plaintext: Uint8Array;
  aad?: string;
  encryptedRow: {
    id: string;
    user_id: string;
    bucket_id: string | null;
    updated_at: string;
    alg: string;
  };
}) => MirrorValues;

/** Optional serializer for domain object -> bytes to encrypt */
export type SerializePlainFn<T = any> =
  (obj: T) => { plaintext: Uint8Array; aad?: string };

/** Pair config: one encrypted table <-> one mirror table with custom columns */
export type EncryptedPairConfig<TSerialize = any> = {
  name: string;
  encryptedTable: string;         // visible to PowerSync (Sync Rules `type`)
  mirrorTable: string;            // local-only plaintext table with custom columns
  mirrorColumns: MirrorColumnDef[]; // custom columns (id/user_id/bucket_id/updated_at are implicit)
  aad?: string;                    // default AAD for encryption
  parsePlain: ParsePlainFn;        // bytes -> column values
  serializePlain?: SerializePlainFn<TSerialize>; // object -> bytes (optional)
  mirrorExtraIndexes?: string[];   // optional: extra CREATE INDEX statements
};

export type EncryptedRuntime = {
  db: AbstractPowerSyncDatabase;
  userId: string;
  crypto: CryptoProvider;
};

export type MirrorBaseRow = {
  id: string;
  user_id: string;
  bucket_id: string | null;
  updated_at: string;   // ISO 8601
};



export type RawEncryptedRow = EncryptedColumns & {
  id: string;
  user_id: string;
  bucket_id: string | null;
  updated_at: string;
  // ...any extra SELECTed columns can go here
};

/**
 * Utility: columns -> envelope for decrypt(), now **generic & type-safe**.
 * Constrain T so the compiler ensures the required fields exist.
 *
 * Usage:
 *   type RawRow = EnvelopeColumns & { id: string; user_id: string; ... };
 *   const env = columnsToEnvelope<RawRow>(row);
 */
export function columnsToEnvelope<T extends EncryptedColumns>(args: T): CipherEnvelope {
  return {
    header: {
      v: 1,
      alg: args.alg,
      aad: args.aad ?? undefined,
      kdf: { saltB64: args.kdf_salt_b64 ?? "" }
    },
    nB64: args.nonce_b64,
    cB64: args.cipher_b64
  };
}

/** Utility: UTF-8 encoder (no external dep) */
export function utf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}