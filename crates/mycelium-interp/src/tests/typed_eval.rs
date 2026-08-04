//! S-TYPED-PRIM-ENV: `prim:` registry → `Interpreter::eval` dispatch-bridge integration tests.
//!
//! Mirrors `tests/wild.rs`'s shape (IR fixtures matching the `wild { … }` → `Node::Op { prim:
//! "wild:…" }` lowering) for the disjoint `prim:` namespace: a `prim:name(args)` call site
//! (`mycelium-l1`'s eventual lowering target for `S-TYPED-PRIM-CALL-CHECK`) evaluates through a
//! [`TypedPrimRegistry`] installed via [`Interpreter::with_typed_prims`] — not through the
//! `wild:` host-op table, and not through the untyped built-in `self.prims` table either.

use mycelium_core::{GuaranteeStrength, Meta, Payload, Provenance, Repr, Value};

use crate::{
    EvalError, HostCapabilities, HostOpRegistry, Interpreter, PrimSig, TySpec, TypedPrimRegistry,
    WidthSpec,
};

fn bin1(bit: bool) -> Value {
    Value::new(
        Repr::Binary { width: 1 },
        Payload::Bits(vec![bit]),
        Meta::exact(Provenance::Root),
    )
    .unwrap()
}

fn typed_op(name: &str, args: Vec<Value>) -> mycelium_core::Node {
    mycelium_core::Node::Op {
        prim: format!("prim:{name}"),
        args: args.into_iter().map(mycelium_core::Node::Const).collect(),
    }
}

/// A trivial checked identity prim: proves a `prim:` op registered in a [`TypedPrimRegistry`]
/// and installed via [`Interpreter::with_typed_prims`] is not just *checkable* (the registry can
/// answer `has_typed`/`get_typed`) but actually **executes** end to end through `eval`, returning
/// the real computed value (not a stub/placeholder).
fn typed_not(prim: &str, args: &[&Value]) -> Result<Value, EvalError> {
    match args {
        [v] => {
            let bit = match v.payload() {
                Payload::Bits(b) if b.len() == 1 => !b[0],
                _ => {
                    return Err(EvalError::PrimType {
                        prim: prim.to_owned(),
                        why: "typed_not expects Binary{1}".into(),
                    })
                }
            };
            Ok(bin1(bit))
        }
        _ => Err(EvalError::PrimType {
            prim: prim.to_owned(),
            why: "typed_not expects 1 arg".into(),
        }),
    }
}

fn not_sig() -> PrimSig {
    PrimSig {
        name: "smoke_not".to_owned(),
        params: vec![TySpec::Binary(WidthSpec(1))],
        ret: TySpec::Binary(WidthSpec(1)),
        effects: vec![],
        guarantee: GuaranteeStrength::Exact,
    }
}

fn interp_with_smoke_not() -> Interpreter {
    let mut reg = TypedPrimRegistry::empty();
    reg.register_typed("smoke_not", not_sig(), typed_not);
    Interpreter::default().with_typed_prims(reg)
}

/// The end-to-end case the bridge exists for: a prim registered (`register_typed`), checkable
/// (`has_typed`/`sigs`), and **executed** through `Interpreter::eval` — not merely resolvable in
/// the registry in isolation, as `typed.rs`'s own unit tests already cover.
#[test]
fn registered_typed_prim_executes_through_eval() {
    let interp = interp_with_smoke_not();
    let node = typed_op("smoke_not", vec![bin1(true)]);
    let v = interp.eval(&node).expect("smoke_not must evaluate");
    match v.payload() {
        Payload::Bits(b) => assert_eq!(b, &[false], "typed_not(true) must compute false"),
        other => panic!("expected Bits payload, got {other:?}"),
    }

    // And the other direction, so this is provably real dispatch, not a hardcoded return.
    let v2 = interp
        .eval(&typed_op("smoke_not", vec![bin1(false)]))
        .expect("smoke_not must evaluate");
    match v2.payload() {
        Payload::Bits(b) => assert_eq!(b, &[true], "typed_not(false) must compute true"),
        other => panic!("expected Bits payload, got {other:?}"),
    }
}

/// Accepts the already-`prim:`-prefixed dispatch key at registration too (mirrors
/// `TypedPrimRegistry`'s own bare-or-prefixed acceptance).
#[test]
fn prefixed_registration_name_also_dispatches() {
    let mut reg = TypedPrimRegistry::empty();
    reg.register_typed("prim:smoke_not", not_sig(), typed_not);
    let interp = Interpreter::default().with_typed_prims(reg);
    let v = interp
        .eval(&typed_op("smoke_not", vec![bin1(true)]))
        .expect("smoke_not must evaluate");
    assert_eq!(v.payload(), &Payload::Bits(vec![false]));
}

/// An unresolved `prim:<name>` is the same loud, typed [`EvalError::UnknownPrim`] miss `wild:`
/// produces on a registry gap — never a panic, never a silent fallback to the untyped
/// `self.prims` built-in table (a `prim:` key must not accidentally resolve as if it were a
/// bare/`wild:` name).
#[test]
fn unregistered_typed_prim_is_loud_unknown_prim_miss() {
    let interp = Interpreter::default();
    let err = interp
        .eval(&typed_op("not_a_registered_typed_prim", vec![bin1(true)]))
        .expect_err("unregistered prim: must miss");
    assert!(
        matches!(&err, EvalError::UnknownPrim(p) if p == "prim:not_a_registered_typed_prim"),
        "expected UnknownPrim(\"prim:not_a_registered_typed_prim\"), got {err:?}"
    );

    // Still misses with a *populated but different* registry — no "any registered prim will
    // do" fallback.
    let interp2 = interp_with_smoke_not();
    let err2 = interp2
        .eval(&typed_op("also_unregistered", vec![bin1(true)]))
        .expect_err("different unregistered prim: must also miss");
    assert!(matches!(
        &err2,
        EvalError::UnknownPrim(p) if p == "prim:also_unregistered"
    ));
}

/// Gating-preservation: installing a populated [`TypedPrimRegistry`] must not open, weaken, or
/// bypass the separate `wild:` host-op gate. `wild:smoke_not` (a `wild:`-namespaced key that
/// happens to share a name with a registered typed prim) still needs its own `HostOpRegistry` +
/// `ffi` grant and must still miss — a typed-prim install must not accidentally make `wild:`
/// ops resolve through `typed_prims`, or vice versa.
#[test]
fn typed_prim_install_does_not_leak_into_wild_dispatch() {
    let interp = interp_with_smoke_not();
    let err = interp
        .eval(&mycelium_core::Node::Op {
            prim: "wild:smoke_not".to_owned(),
            args: vec![mycelium_core::Node::Const(bin1(true))],
        })
        .expect_err("wild:smoke_not must still miss with no host-op floor installed");
    assert!(
        matches!(&err, EvalError::UnknownPrim(p) if p == "wild:smoke_not"),
        "wild: dispatch must stay gated by HostOpRegistry/ffi, not fall through to \
         typed_prims; got {err:?}"
    );
}

/// Symmetric check: `Interpreter::default()` (no typed prims installed) plus
/// `with_host_floor`-shaped host ops must not make a `prim:` key resolve through `wild:`'s
/// `HostOpRegistry`/`PrimRegistry` tables either — the two namespaces stay disjoint in both
/// directions.
#[test]
fn wild_registry_does_not_leak_into_typed_prim_dispatch() {
    let host_ops = HostOpRegistry::empty();
    let interp = Interpreter::default().with_host_ops(host_ops, HostCapabilities::default());
    let err = interp
        .eval(&typed_op("smoke_not", vec![bin1(true)]))
        .expect_err("prim:smoke_not must miss when no TypedPrimRegistry entry is installed");
    assert!(matches!(
        &err,
        EvalError::UnknownPrim(p) if p == "prim:smoke_not"
    ));
}
