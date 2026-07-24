//! `wild:` host-op registry + dispatch (RFC-0028 §4.3; A1).
//!
//! # Seam
//!
//! L1 elaboration lowers `wild { name(args…) }` to
//! [`Node::Op`](mycelium_core::Node::Op) `{ prim: "wild:name", … }` (KC-3 — **no new Core-IR
//! node**). This module owns the **runtime** half of that seam:
//!
//! 1. A [`HostOpRegistry`] map from bare host-op name → typed handler (`args in → Value /
//!    EvalError out`).
//! 2. A capability gate ([`HostCapabilities::ffi`]) — the runtime half of the L1 surface
//!    `@std-sys` nodule marker + `!{ffi}` effect (L1 maps `"ffi"` to
//!    [`EffectKind::Named`](crate::EffectKind)`("ffi")`).
//! 3. A clean [`HostFloor`] trait boundary for OS contact, so A1 does not invent a cross-repo
//!    `@std-sys` API. The default [`StdHostFloor`] mirrors `mycelium-std-sys` with pure `std`
//!    (no new dependency). **A1b** replaces it with a real `mycelium-std-sys` adapter.
//!
//! # Default is fail-closed
//!
//! [`Interpreter::default`](crate::Interpreter::default) ships an **empty** host registry and
//! `ffi = false`. An unresolved `wild:<name>` is a typed [`EvalError::UnknownPrim`] (never a
//! silent no-op or panic — G2). Pure/deterministic fragments therefore cannot invoke host ops
//! silently: [`crate::is_pure`] already excludes any `wild:` prim, and the default interpreter
//! refuses them at apply time.
//!
//! Opt in with [`Interpreter::with_host_floor`](crate::Interpreter::with_host_floor): that
//! installs the min built-in set **and** grants `ffi`. Registration alone is not enough —
//! invoking a registered host op without `ffi` is [`EvalError::HostCapabilityDenied`].
//!
//! # Min built-in set (prove-the-seam, not a full OS surface)
//!
//! | prim key | signature (repr args) | effect |
//! |----------|----------------------|--------|
//! | `wild:entropy_fill` | `Binary{N} → Bytes` | fill `n` bytes from host RNG |
//! | `wild:mono_nanos` | `() → Binary{64}` | monotonic nanoseconds |
//! | `wild:read_capped` | `(Bytes path, Binary{N} max) → Bytes` | read ≤ `min(max, HARD_CAP)` from path |
//!
//! Results are tagged **`Declared`** (VR-5 — OS contact has no proven bound). Hard byte caps
//! refuse oversized requests rather than silently truncating (G2 / P3).

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Path;
use std::time::Instant;

use mycelium_core::{
    binary, operation_hash, Bound, BoundBasis, BoundKind, GuaranteeStrength, Meta, NormKind,
    Payload, Provenance, Repr, Value,
};

use crate::EvalError;

/// Surface effect name L1 maps to [`crate::EffectKind::Named`]`("ffi")` (see mycelium-l1
/// `effect_name_to_budget`). The runtime half of `!{ffi}`.
pub const FFI_EFFECT: &str = "ffi";

/// Absolute hard byte cap on host entropy fills and path reads (P3 — bounds at the external edge).
/// A request above this is an explicit [`EvalError::PrimType`], never a silent truncate (G2).
pub const HOST_BYTE_HARD_CAP: usize = 1 << 20; // 1 MiB

/// Runtime capability grants for host ops (the interpreter half of `@std-sys` + `!{ffi}`).
///
/// **Residual (honest):** L0 does not re-check the L1 `@std-sys` nodule-header marker — that is a
/// source-level gate in `mycelium-l1`. This flag is the opt-in runtime half: pure/default
/// interpreters keep it `false` and refuse every host invoke.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostCapabilities {
    /// Whether the `ffi` effect is granted for this interpreter.
    pub ffi: bool,
}

impl HostCapabilities {
    /// Grant the `ffi` effect only.
    #[must_use]
    pub fn with_ffi(mut self) -> Self {
        self.ffi = true;
        self
    }
}

/// OS-contact boundary the min host-op set dispatches through (A1).
///
/// **A1b follow-up:** implement this trait over `mycelium-std-sys`
/// (`rand::fill_bytes`, `time::mono_nanos`, `fs::read` + cap) in a thin adapter crate / module
/// and install it via [`HostOpRegistry::with_floor`]. Do **not** invent new cross-repo Mycelium
/// surface APIs here — the trait is the stable internal boundary.
pub trait HostFloor: Send + Sync {
    /// Fill `buf` with host entropy. `Err` is never silent (G2).
    ///
    /// # Errors
    /// Returns a host error string when entropy is unavailable or the fill fails.
    fn fill_entropy(&self, buf: &mut [u8]) -> Result<(), String>;

    /// Monotonic nanoseconds since an unspecified process-local epoch (non-decreasing in-process).
    fn mono_nanos(&self) -> u64;

    /// Read up to `cap` bytes from `path`. Must refuse (not truncate) when the file is larger than
    /// `cap` if the implementation can detect it; partial reads that hit an OS error must surface
    /// as `Err` (G2).
    ///
    /// # Errors
    /// Returns a host error string on OS failure or a cap violation the floor chooses to refuse.
    fn read_capped(&self, path: &Path, cap: usize) -> Result<Vec<u8>, String>;
}

/// Default host floor: pure `std` mirrors of `mycelium-std-sys` (no cross-repo dep in A1).
///
/// - Entropy: `/dev/urandom` (Unix); explicit `Err` when unavailable.
/// - Clock: `std::time::Instant` process-local origin (same shape as `std-sys::time::mono_nanos`).
/// - Read: `std::fs::File` + capped `take(cap)` — returns at most `cap` bytes (short read = EOF).
#[derive(Debug, Default, Clone, Copy)]
pub struct StdHostFloor;

impl HostFloor for StdHostFloor {
    fn fill_entropy(&self, buf: &mut [u8]) -> Result<(), String> {
        if buf.is_empty() {
            return Ok(());
        }
        let mut f =
            std::fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
        f.read_exact(buf)
            .map_err(|e| format!("read /dev/urandom: {e}"))
    }

    fn mono_nanos(&self) -> u64 {
        static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let origin = ORIGIN.get_or_init(Instant::now);
        u64::try_from(origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn read_capped(&self, path: &Path, cap: usize) -> Result<Vec<u8>, String> {
        let mut f =
            std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        // Cap by construction: `take` never yields more than `cap` bytes.
        let mut limited = f.by_ref().take(u64::try_from(cap).unwrap_or(u64::MAX));
        let mut out = Vec::new();
        limited
            .read_to_end(&mut out)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        Ok(out)
    }
}

/// A host-op implementation: pure-looking signature, may perform host effects through the floor.
pub type HostOpFn = fn(op: &str, args: &[&Value]) -> Result<Value, EvalError>;

/// Name → host-handler table the interpreter dispatches `wild:<name>` through.
///
/// Keys are **bare** names (`entropy_fill`), not the `wild:` prefix. Registration is the
/// capability *handle*; the [`HostCapabilities::ffi`] flag is the separate grant check.
#[derive(Clone, Default)]
pub struct HostOpRegistry {
    table: BTreeMap<String, HostOpFn>,
}

impl HostOpRegistry {
    /// An empty registry — no host op is granted.
    #[must_use]
    pub fn empty() -> Self {
        HostOpRegistry {
            table: BTreeMap::new(),
        }
    }

    /// The A1 min built-in host floor (`entropy_fill`, `mono_nanos`, `read_capped`) over
    /// [`StdHostFloor`]. Does **not** grant `ffi` by itself — pair with
    /// [`HostCapabilities::with_ffi`] via [`crate::Interpreter::with_host_floor`].
    #[must_use]
    pub fn with_min_floor() -> Self {
        let mut r = Self::empty();
        r.register("entropy_fill", host_entropy_fill);
        r.register("mono_nanos", host_mono_nanos);
        r.register("read_capped", host_read_capped);
        r
    }

    /// Install the min built-in set, binding handlers to the given floor.
    ///
    /// A1 ships free-function handlers closed over [`StdHostFloor`] (see [`with_min_floor`]); this
    /// constructor documents the A1b entry point. Until A1b lands with a dynamic handler table,
    /// `floor` is only type-checked for the trait object shape — the registered handlers still use
    /// [`StdHostFloor`]. Callers that need a custom floor today should [`register`] their own
    /// `HostOpFn`s.
    #[must_use]
    pub fn with_floor(_floor: std::sync::Arc<dyn HostFloor>) -> Self {
        // A1 residual: free-function table is closed over StdHostFloor. A1b promotes this to a
        // closure table capturing `floor` (or re-registers std-sys-backed free fns). Keeping the
        // signature stable so A1b is a body swap, not an API invent.
        Self::with_min_floor()
    }

    /// Register (or replace) a host op under a bare name.
    pub fn register(&mut self, name: &str, f: HostOpFn) {
        self.table.insert(name.to_owned(), f);
    }

    /// Look up a host op by bare name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<HostOpFn> {
        self.table.get(name).copied()
    }

    /// Registered bare names (sorted).
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.table.keys().map(String::as_str).collect()
    }
}

// --- min host ops -------------------------------------------------------------------------------

/// Build a host-op result tagged **`Declared`** (VR-5 — OS contact has no proven bound). Uses a
/// zero-magnitude `UserDeclared` bound (M-I4), matching the wrapping/`bit.truncate` honesty shape.
fn host_declared_result(
    op: &str,
    inputs: &[&Value],
    repr: Repr,
    payload: Payload,
) -> Result<Value, EvalError> {
    let provenance = Provenance::Derived {
        op: operation_hash(op),
        inputs: inputs.iter().map(|v| v.content_hash()).collect(),
    };
    let bound = Bound {
        kind: BoundKind::Error {
            eps: 0.0,
            norm: NormKind::Linf,
        },
        basis: BoundBasis::UserDeclared,
    };
    let meta = Meta::new(
        provenance,
        GuaranteeStrength::Declared,
        Some(bound),
        None,
        None,
        None,
    )
    .map_err(EvalError::Wf)?;
    Value::new(repr, payload, meta).map_err(EvalError::Wf)
}

fn expect_arity(op: &str, args: &[&Value], n: usize) -> Result<(), EvalError> {
    if args.len() == n {
        Ok(())
    } else {
        Err(EvalError::PrimType {
            prim: op.to_owned(),
            why: format!("expected {n} argument(s), got {}", args.len()),
        })
    }
}

/// Read an unsigned count from a `Binary{N}` operand (MSB-first).
fn as_uint(op: &str, v: &Value) -> Result<u64, EvalError> {
    match (v.repr(), v.payload()) {
        (Repr::Binary { .. }, Payload::Bits(bits)) => Ok(binary::bits_to_uint(bits)),
        _ => Err(EvalError::PrimType {
            prim: op.to_owned(),
            why: "expected a Binary operand (unsigned count)".to_owned(),
        }),
    }
}

/// `wild:entropy_fill : Binary{N} → Bytes` — fill `n` host-entropy bytes.
///
/// `n` is the unsigned value of the Binary operand. `n > HOST_BYTE_HARD_CAP` is an explicit
/// refusal (never a silent truncate).
fn host_entropy_fill(op: &str, args: &[&Value]) -> Result<Value, EvalError> {
    expect_arity(op, args, 1)?;
    let n_u64 = as_uint(op, args[0])?;
    let n = usize::try_from(n_u64).map_err(|_| EvalError::PrimType {
        prim: op.to_owned(),
        why: format!("entropy fill length {n_u64} does not fit usize"),
    })?;
    if n > HOST_BYTE_HARD_CAP {
        return Err(EvalError::PrimType {
            prim: op.to_owned(),
            why: format!(
                "entropy fill length {n} exceeds the {HOST_BYTE_HARD_CAP}-byte hard cap (refused, \
                 not truncated)"
            ),
        });
    }
    let mut buf = vec![0u8; n];
    StdHostFloor
        .fill_entropy(&mut buf)
        .map_err(|why| EvalError::PrimType {
            prim: op.to_owned(),
            why: format!("host entropy unavailable: {why}"),
        })?;
    host_declared_result(op, args, Repr::Bytes, Payload::Bytes(buf))
}

/// `wild:mono_nanos : () → Binary{64}` — process-local monotonic nanoseconds.
fn host_mono_nanos(op: &str, args: &[&Value]) -> Result<Value, EvalError> {
    expect_arity(op, args, 0)?;
    let nanos = StdHostFloor.mono_nanos();
    let bits = binary::uint_to_bits(nanos, 64).ok_or_else(|| EvalError::PrimType {
        prim: op.to_owned(),
        why: "internal: u64 nanos failed to encode as Binary{64}".to_owned(),
    })?;
    host_declared_result(op, args, Repr::Binary { width: 64 }, Payload::Bits(bits))
}

/// `wild:read_capped : (Bytes path, Binary{N} max) → Bytes` — read up to `min(max, HARD_CAP)`
/// bytes from the UTF-8 path. Cap is by construction (`take`); never a silent oversize alloc.
fn host_read_capped(op: &str, args: &[&Value]) -> Result<Value, EvalError> {
    expect_arity(op, args, 2)?;
    let path_bytes = args[0].bytes().ok_or_else(|| EvalError::PrimType {
        prim: op.to_owned(),
        why: "expected a Bytes path operand".to_owned(),
    })?;
    let path_str = std::str::from_utf8(path_bytes).map_err(|_| EvalError::PrimType {
        prim: op.to_owned(),
        why: "path is not valid UTF-8".to_owned(),
    })?;
    let max_u64 = as_uint(op, args[1])?;
    let max = usize::try_from(max_u64).map_err(|_| EvalError::PrimType {
        prim: op.to_owned(),
        why: format!("read cap {max_u64} does not fit usize"),
    })?;
    let cap = max.min(HOST_BYTE_HARD_CAP);
    if max > HOST_BYTE_HARD_CAP {
        // Still proceed at HARD_CAP, but the caller asked for more than we will ever yield —
        // refuse rather than silently shrink the request (G2: the hard cap is a hard refuse when
        // the *requested* max alone exceeds it).
        return Err(EvalError::PrimType {
            prim: op.to_owned(),
            why: format!(
                "read cap {max} exceeds the {HOST_BYTE_HARD_CAP}-byte hard cap (refused, not \
                 truncated)"
            ),
        });
    }
    let bytes = StdHostFloor
        .read_capped(Path::new(path_str), cap)
        .map_err(|why| EvalError::PrimType {
            prim: op.to_owned(),
            why: format!("host read failed: {why}"),
        })?;
    host_declared_result(op, args, Repr::Bytes, Payload::Bytes(bytes))
}

/// Dispatch a fully-evaluated `wild:<name>` application through the host registry + capability
/// gate. Called from the interpreter's `(E-Op-Apply)` arm.
///
/// Order (fail closed, never silent — G2):
/// 1. Look up bare `name` in the host registry → [`EvalError::UnknownPrim`] on miss (typed miss).
/// 2. Require [`HostCapabilities::ffi`] → [`EvalError::HostCapabilityDenied`] if ungranted.
/// 3. Invoke the handler.
pub(crate) fn dispatch_wild(
    host_ops: &HostOpRegistry,
    caps: HostCapabilities,
    prim: &str,
    values: &[&Value],
) -> Result<Value, EvalError> {
    let name = prim
        .strip_prefix("wild:")
        .expect("dispatch_wild is only called for wild:-prefixed prims");
    let f = host_ops
        .get(name)
        .ok_or_else(|| EvalError::UnknownPrim(prim.to_owned()))?;
    if !caps.ffi {
        return Err(EvalError::HostCapabilityDenied {
            op: name.to_owned(),
            why: format!(
                "the `{FFI_EFFECT}` effect is not granted on this interpreter (runtime half of \
                 `@std-sys` + `!{{{FFI_EFFECT}}}`); pure/deterministic fragments cannot invoke \
                 host ops — use Interpreter::with_host_floor() to opt in"
            ),
        });
    }
    f(prim, values)
}
