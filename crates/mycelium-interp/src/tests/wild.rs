//! A1: `wild:` host-op registry + dispatch integration tests (RFC-0028 §4.3).
//!
//! Elaboration lives in `mycelium-l1` (not this repo): it lowers `wild { name(args) }` to
//! `Node::Op { prim: "wild:name", … }`. These tests use **IR fixtures** that match that lowering
//! exactly, so a host-shaped program both *elaborates* (by construction of the fixture) and
//! *evaluates* through the new registry — and an unknown wild name yields the typed miss.

use mycelium_core::{binary, GuaranteeStrength, Meta, Payload, Provenance, Repr, Value};

use crate::{
    EvalError, HostCapabilities, HostOpRegistry, IdentitySwapEngine, Interpreter, PrimRegistry,
    HOST_BYTE_HARD_CAP,
};

fn bin_u64(n: u64) -> Value {
    let bits = binary::uint_to_bits(n, 64).expect("u64 fits Binary{64}");
    Value::new(
        Repr::Binary { width: 64 },
        Payload::Bits(bits),
        Meta::exact(Provenance::Root),
    )
    .unwrap()
}

fn bin_u8(n: u8) -> Value {
    let bits: Vec<bool> = (0..8).rev().map(|k| (n >> k) & 1 == 1).collect();
    Value::new(
        Repr::Binary { width: 8 },
        Payload::Bits(bits),
        Meta::exact(Provenance::Root),
    )
    .unwrap()
}

fn bytes_val(b: &[u8]) -> Value {
    Value::new(
        Repr::Bytes,
        Payload::Bytes(b.to_vec()),
        Meta::exact(Provenance::Root),
    )
    .unwrap()
}

fn wild_op(name: &str, args: Vec<Value>) -> mycelium_core::Node {
    mycelium_core::Node::Op {
        prim: format!("wild:{name}"),
        args: args.into_iter().map(mycelium_core::Node::Const).collect(),
    }
}

/// IR fixture for `wild { mono_nanos() }` — the elaboration shape L1 produces.
#[test]
fn wild_mono_nanos_elaborates_and_evaluates_through_registry() {
    let interp = Interpreter::default().with_host_floor();
    let node = wild_op("mono_nanos", vec![]);
    let v = interp.eval(&node).expect("mono_nanos must evaluate");
    assert_eq!(v.repr(), &Repr::Binary { width: 64 });
    assert_eq!(
        v.meta().guarantee(),
        GuaranteeStrength::Declared,
        "host results are Declared (VR-5), never Exact"
    );
    // A second read is non-decreasing (process-local monotonic clock).
    let v2 = interp
        .eval(&wild_op("mono_nanos", vec![]))
        .expect("second mono_nanos");
    let t0 = match v.payload() {
        Payload::Bits(b) => binary::bits_to_uint(b.as_slice()),
        _ => panic!("expected Bits payload"),
    };
    let t1 = match v2.payload() {
        Payload::Bits(b) => binary::bits_to_uint(b.as_slice()),
        _ => panic!("expected Bits payload"),
    };
    assert!(t1 >= t0, "mono clock must be non-decreasing: {t0} → {t1}");
}

/// IR fixture for `wild { entropy_fill(n) }`.
#[test]
fn wild_entropy_fill_elaborates_and_evaluates_through_registry() {
    let interp = Interpreter::default().with_host_floor();
    let node = wild_op("entropy_fill", vec![bin_u8(16)]);
    match interp.eval(&node) {
        Ok(v) => {
            assert_eq!(v.repr(), &Repr::Bytes);
            assert_eq!(v.bytes().expect("bytes").len(), 16);
            assert_eq!(v.meta().guarantee(), GuaranteeStrength::Declared);
        }
        Err(EvalError::PrimType { why, .. }) if why.contains("entropy unavailable") => {
            // Non-Unix hosts fail closed (honest) — not a silent zero-fill.
        }
        Err(e) => panic!("unexpected entropy_fill error: {e}"),
    }
}

/// IR fixture for `wild { read_capped(path, max) }` against a temp file.
#[test]
fn wild_read_capped_elaborates_and_evaluates_through_registry() {
    let dir = std::env::temp_dir();
    let path = dir.join("mycelium_a1_wild_read_capped.bin");
    let contents = b"a1-host-read-fixture";
    std::fs::write(&path, contents).expect("write fixture");
    let path_bytes = path.to_string_lossy().into_owned();

    let interp = Interpreter::default().with_host_floor();
    let node = wild_op(
        "read_capped",
        vec![bytes_val(path_bytes.as_bytes()), bin_u64(64)],
    );
    let v = interp.eval(&node).expect("read_capped must evaluate");
    assert_eq!(v.bytes().expect("bytes"), contents);
    assert_eq!(v.meta().guarantee(), GuaranteeStrength::Declared);

    let _ = std::fs::remove_file(&path);
}

/// Unknown `wild:<name>` is a **typed miss** — never silent, never panic.
#[test]
fn unknown_wild_name_is_typed_miss() {
    let interp = Interpreter::default().with_host_floor();
    let node = wild_op("not_a_registered_host_op", vec![]);
    let err = interp.eval(&node).expect_err("unknown wild must miss");
    assert!(
        matches!(&err, EvalError::UnknownPrim(p) if p == "wild:not_a_registered_host_op"),
        "expected UnknownPrim typed miss, got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("host-op-not-registered") && msg.contains("not_a_registered_host_op"),
        "Display must name the typed miss; got: {msg:?}"
    );
}

/// Default interpreter (no host floor) refuses every wild: as typed miss — pure fragment safety.
#[test]
fn default_interpreter_refuses_all_wild_as_typed_miss() {
    let interp = Interpreter::default();
    for name in ["entropy_fill", "mono_nanos", "read_capped", "foreign"] {
        let err = interp
            .eval(&wild_op(name, vec![]))
            .expect_err("default must refuse wild");
        assert!(
            matches!(err, EvalError::UnknownPrim(ref p) if p == &format!("wild:{name}")),
            "default path: expected UnknownPrim for wild:{name}, got {err:?}"
        );
    }
}

/// Registered host op + ungranted `ffi` → fail-closed capability denial (determinism residual closed).
#[test]
fn registered_host_op_without_ffi_is_capability_denied() {
    let interp = Interpreter::default().with_host_ops(
        HostOpRegistry::with_min_floor(),
        HostCapabilities::default(), // ffi = false
    );
    let err = interp
        .eval(&wild_op("mono_nanos", vec![]))
        .expect_err("ffi ungranted must deny");
    assert!(
        matches!(err, EvalError::HostCapabilityDenied { ref op, .. } if op == "mono_nanos"),
        "expected HostCapabilityDenied, got {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("ffi") || msg.contains("capability"),
        "Display must explain the capability gate; got: {msg:?}"
    );
}

/// Hard byte cap: oversize entropy fill is refused, not truncated.
#[test]
fn entropy_fill_hard_cap_refuses_oversize() {
    let interp = Interpreter::default().with_host_floor();
    let over = (HOST_BYTE_HARD_CAP as u64) + 1;
    let err = interp
        .eval(&wild_op("entropy_fill", vec![bin_u64(over)]))
        .expect_err("oversize must refuse");
    assert!(
        matches!(err, EvalError::PrimType { .. }),
        "expected PrimType hard-cap refusal, got {err:?}"
    );
    assert!(
        err.to_string().contains("hard cap"),
        "must name the hard cap; got: {err}"
    );
}

/// `wild:` never routes through the pure PrimRegistry even if a colliding name is registered there.
#[test]
fn wild_prefix_never_dispatches_through_pure_prim_registry() {
    let mut prims = PrimRegistry::empty();
    // A malicious/mistaken registration of a wild: key into the pure table must be ignored.
    prims.register("wild:mono_nanos", |_p, _a| {
        panic!("pure PrimRegistry must not handle wild:");
    });
    let interp = Interpreter::new(prims, Box::new(IdentitySwapEngine)).with_host_floor();
    // Host floor still wins; no panic from the pure-table trap.
    let v = interp
        .eval(&wild_op("mono_nanos", vec![]))
        .expect("host path must win");
    assert_eq!(v.repr(), &Repr::Binary { width: 64 });
}
