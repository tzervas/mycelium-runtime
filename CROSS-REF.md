# CROSS-REF — mycelium-runtime

Mycelium-internal dependencies only (steer handoff §6.1; external crates stay in Cargo
metadata). Pinned revs are the fixed (buildable) tips recorded by the Phase-B wave;
content hash = git tree hash of the pinned rev.

| Interface consumed | Repo | Pinned rev | Content hash | Notes |
|---|---|---|---|---|
| mycelium-core | https://github.com/tzervas/mycelium-core | `46d2515cbd86d2ae4d1365f4adcd2796737e9f0b` | tree `(tree hash: fetch dep rev locally to resolve)` | Rust API of `mycelium-core` (see monorepo `docs/api-index/INDEX.md#mycelium-core`) |
| mycelium-dense | https://github.com/tzervas/mycelium-value | `6d230ad2023a716704c697ac6812a2062624b4eb` | tree `(tree hash: fetch dep rev locally to resolve)` | Rust API of `mycelium-dense` (see monorepo `docs/api-index/INDEX.md#mycelium-dense`) |
| mycelium-numerics | https://github.com/tzervas/mycelium-value | `6d230ad2023a716704c697ac6812a2062624b4eb` | tree `(tree hash: fetch dep rev locally to resolve)` | Rust API of `mycelium-numerics` (see monorepo `docs/api-index/INDEX.md#mycelium-numerics`) |
| mycelium-vsa | https://github.com/tzervas/mycelium-value | `6d230ad2023a716704c697ac6812a2062624b4eb` | tree `(tree hash: fetch dep rev locally to resolve)` | Rust API of `mycelium-vsa` (see monorepo `docs/api-index/INDEX.md#mycelium-vsa`) |
| mycelium-workstack | https://github.com/tzervas/mycelium-core | `46d2515cbd86d2ae4d1365f4adcd2796737e9f0b` | tree `(tree hash: fetch dep rev locally to resolve)` | Rust API of `mycelium-workstack` (see monorepo `docs/api-index/INDEX.md#mycelium-workstack`) |

**Owning docs:** RFC-0002 · RFC-0034 · RFC-0013 (certs, modes, diagnostics, interpreter).
**Source provenance:** extracted from `tzervas/mycelium` archive `aad96b7a…`; fixed by
the course-correction Phase B (workspace root, git pins, toolchain + supply-chain
replicas, CI v2). Full program record: monorepo
`docs/planning/course-correction-2026-07-18/PROGRAM.md`.
