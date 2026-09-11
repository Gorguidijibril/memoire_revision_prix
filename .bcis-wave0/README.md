# BCI-S Wave 0 PostgreSQL runner

Temporary isolated runner for the BCI-S Wave 0 gate. Do not merge this branch into `main`.

PostgreSQL execution order:
1. 001, 002, 003, 005, 006, 009
2. schema assertion
3. Golden v0.2 seed + assertions + negative constraints
4. deferred constraint validation
5. 25-way concurrency gate
6. RLS fixture
7. 010 OIDC/RLS activation
8. non-owner RLS offensive tests

Excluded intentionally:
- 004: legacy Golden seed, superseded by `golden_seed_v02.sql`
- 007: SQLite-only migration (`PRAGMA`), never PostgreSQL
- 008: reserved / not applicable

`DATABASE_URL` is injected by Render `fromDatabase`; it must never be committed or printed.
