# Changelog — mycelium-runtime

## Unreleased

### A1 — `wild:` host-op registry + dispatch (`mycelium-interp`)

Closes the runtime host miss for L1-elaborated `wild { name(args) }` programs
(lowered to `Node::Op { prim: "wild:name", … }`, RFC-0028 §4.3).

**What now runs**

- `HostOpRegistry` + `HostCapabilities::ffi` on `Interpreter`.
- Dispatch site: `Interpreter::step_budgeted` `(E-Op-Apply)` routes `wild:`
  exclusively through `wild::dispatch_wild` (never the pure `PrimRegistry`).
- Opt-in: `Interpreter::with_host_floor()` installs the min built-in set **and**
  grants `ffi`. Default interpreter remains fail-closed (empty registry, no `ffi`).
- Min built-ins (all `Declared`, hard 1 MiB byte cap where applicable):
  - `wild:entropy_fill` — host RNG fill
  - `wild:mono_nanos` — monotonic clock
  - `wild:read_capped` — capped path read
- Typed miss: unknown `wild:<name>` → `EvalError::UnknownPrim` (Display:
  `host-op-not-registered`).
- Capability denial: registered + `ffi = false` →
  `EvalError::HostCapabilityDenied`.
- Determinism: `is_pure` already excludes `wild:`; default interpreter refuses
  every host invoke.

**Docs corrected**

- Stale “host miss / empty registry only” and any “wild Residual-at-elab”
  wording for the runtime: elaboration succeeds; A1 makes the min set
  **evaluable** when the host floor is opted in. Residual is A1b (`std-sys`
  adapter + L1 `@std-sys` marker remains source-level).

**A1b follow-up (not in this change)**

- Implement `HostFloor` over `mycelium-std-sys` (`rand::fill_bytes`,
  `time::mono_nanos`, `fs::read` + cap) and install via
  `HostOpRegistry::with_floor` / a closure table — no new cross-repo surface
  APIs invented here.
