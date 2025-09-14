import { useQuery } from "@powersync/react";
import type { MirrorBaseRow, EncryptedPairConfig } from "./types.js";


/**
 * Query the PLAINTEXT mirror with typed, declared columns.
 * Returns rows typed as MirrorBaseRow & TFields.
 */
export function useEncryptedQuery<RowType = any>(
  pair: EncryptedPairConfig,
  args: {
    userId: string | null | undefined;
    bucketId?: string | null;
    extraWhere?: string;
    parameters?: any[];
    throttleMs?: number;
    orderBy?: string; // default "updated_at DESC"
  }
) {
  const order = args.orderBy ?? "updated_at DESC";
  const customNames = pair.mirrorColumns.map(c => c.name);
  const selectCols = ["id", "user_id", "bucket_id", "updated_at", ...customNames].join(", ");

  const bucketSql =
    args.bucketId === undefined
      ? ""
      : args.bucketId === null
      ? " AND bucket_id IS NULL "
      : " AND bucket_id = ? ";
  const extra = args.extraWhere ? ` ${args.extraWhere} ` : "";

  const params = (() => {
    const base: any[] = [args.userId ?? ""];
    if (args.bucketId !== undefined && args.bucketId !== null) base.push(args.bucketId);
    return args.parameters ? [...base, ...args.parameters] : base;
  })();

  const sql = `
    SELECT ${selectCols}
      FROM ${pair.mirrorTable}
     WHERE user_id = ?
     ${bucketSql}
     ${extra}
     ORDER BY ${order}
  `;

  // type assertion: array of MirrorBaseRow & TFields
  const q = useQuery<RowType>(sql, params, { throttleMs: args.throttleMs ?? 150 })
  return q;
}