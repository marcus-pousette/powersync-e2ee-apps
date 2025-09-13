PowerSync + Supabase E2EE TODO (Monorepo)

This repo demonstrates end‑to‑end encryption (E2EE) with PowerSync + Supabase. The app stores only non‑sensitive identifiers in plaintext (user/bucket); all payloads are encrypted.

Key packages
- `packages/todo/frontend` — React + Vite app (workspace: `@app/client`)
- `packages/todo/lib` — Reusable data layer (PowerSync repo + SQL)
- `packages/crypto/*` — Crypto interfaces and providers

Quick start
- Install: `yarn install`
- Dev: `yarn workspace @app/client dev`

For detailed setup (envs, DB schema, Supabase CLI, PowerSync connection), see:

- `packages/todo/README.md`

Docs
- PowerSync + Supabase: https://docs.powersync.com/integration-guides/supabase-+-powersync
- Raw SQLite tables: https://releases.powersync.com/announcements/introducing-raw-sqlite-tables-support-experimental
