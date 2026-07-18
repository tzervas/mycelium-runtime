//! Sizing pass (course-correction W-D item 2): measures [`CertStore`]'s two retained pieces —
//! the handle ([`mycelium_core::ContentHash`]) and the stored certificate body
//! ([`SwapCertificate`]) — against `docs/spec/Language-Retention-Policy.md` §5's `hot_cert_handle_cap`
//! (L1) row. Black-box (public-API only — `CertStore`'s fields are private; this belongs in
//! `tests/`, not an in-crate white-box module, per the house test-layout rule).
//!
//! Unlike `mycelium-diag`'s L4 row, L1's §5 table cell is a **count only** (`0`/`256`), with no
//! existing byte-budget figure to check against — so this measurement doesn't verify an existing
//! number, it **adds** a new one (an `Empirical` byte-estimate for the `Certified` cap, stated with
//! its method, never silently asserted). The cap COUNT itself (256) stays `Declared` — a policy
//! choice, not something derived from measurement (VR-5).

use mycelium_cert::store::{cert_content_hash, declared_cert_handle_cap, CertStore};
use mycelium_cert::{BinTernParams, SwapCertificate};
use mycelium_core::{CertMode, ContentHash, Repr};

/// A representative `Bijective` certificate — the class `CertStore` actually retains in this
/// codebase today (binary<->ternary swaps; `mode::gate_swap`'s only caller of `CertStore::insert`).
fn representative_cert() -> SwapCertificate {
    SwapCertificate::Bijective {
        src: Repr::Binary { width: 64 },
        target: Repr::Ternary { trits: 41 },
        policy_used: ContentHash::parse(
            "blake3:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("well-formed"),
        lemma_ref: ContentHash::parse(
            "blake3:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .expect("well-formed"),
        params: BinTernParams {
            width: 64,
            trits: 41,
        },
    }
}

/// Static stack footprint of the handle ([`ContentHash`]) and the stored body ([`SwapCertificate`])
/// — sanity-bounded (not pinned to an exact byte count; a struct-layout-fragile assertion would
/// break on an unrelated field reorder/compiler bump). The actual measured figures (obtained via
/// `cargo test -p mycelium-cert --test sizing -- --nocapture`) are recorded in
/// `docs/spec/Language-Retention-Policy.md` §5, with this test named as the method.
#[test]
fn handle_and_body_stack_sizes_are_sane() {
    let handle_size = std::mem::size_of::<ContentHash>();
    let body_size = std::mem::size_of::<SwapCertificate>();
    assert!(
        handle_size > 0 && handle_size < 256,
        "ContentHash stack size {handle_size}"
    );
    assert!(
        body_size > 0 && body_size < 1024,
        "SwapCertificate stack size {body_size}"
    );
}

/// A rough (never `Exact`) byte estimate of one retained `(handle, body)` pair: stack size plus
/// the handle string's heap capacity plus the body's own `ContentHash` fields' heap capacities
/// (the only variable-size parts of a `Bijective` cert — `Repr`/`BinTernParams` are fixed-size).
fn cert_pair_estimate(handle: &ContentHash, body: &SwapCertificate) -> usize {
    let mut bytes = std::mem::size_of::<ContentHash>() + handle.as_str().len();
    bytes += std::mem::size_of::<SwapCertificate>();
    if let SwapCertificate::Bijective {
        policy_used,
        lemma_ref,
        ..
    } = body
    {
        bytes += policy_used.as_str().len() + lemma_ref.as_str().len();
    }
    bytes
}

/// Synthetic-load measurement: fill a [`CertStore`] to the `Certified` cap
/// ([`declared_cert_handle_cap`]) with distinct representative certs, and report the total
/// estimated bytes retained — the `Empirical` figure that fills the currently-`Declared`-count-only
/// L1 §5 cell with an actual byte estimate (a NEW number, not a check against an existing one — see
/// the module doc note). Exercises the bound (SC-2): the store never exceeds the declared cap
/// regardless of how many certs are inserted, and every excess insert is accounted for via
/// [`CertStore::dropped`] (never a silent overflow).
#[test]
fn synthetic_load_at_certified_cap_reports_estimated_bytes() {
    let cap = declared_cert_handle_cap(CertMode::Certified);
    let mut store = CertStore::new();
    // Insert 2x the cap with DISTINCT bodies (differing `trits` per insert so each has a distinct
    // content hash — an identical repeat would be the documented idempotent no-op path, not
    // exercise eviction).
    for i in 0..(cap * 2) {
        let mut cert = representative_cert();
        if let SwapCertificate::Bijective { params, .. } = &mut cert {
            params.trits = 41 + (i as u32 % 1000); // vary to force distinct content hashes
        }
        store.insert(CertMode::Certified, &cert);
    }
    assert_eq!(store.len(), cap, "the store never exceeds the declared cap");
    assert_eq!(
        store.dropped(),
        cap as u64,
        "exactly (2*cap - cap) = cap inserts were evicted, all accounted for (never silent)"
    );

    // The final-state estimate: exactly the `cap` certs `store` still retains (the last `cap`
    // inserts, per `drop_oldest`) — re-derive the same stream and sum only what `get` still finds.
    let mut retained_estimate = 0usize;
    for i in 0..(cap * 2) {
        let mut cert = representative_cert();
        if let SwapCertificate::Bijective { params, .. } = &mut cert {
            params.trits = 41 + (i as u32 % 1000);
        }
        let handle = cert_content_hash(&cert);
        if store.get(&handle).is_some() {
            retained_estimate += cert_pair_estimate(&handle, &cert);
        }
    }
    assert!(
        retained_estimate > 0,
        "the retained set must contribute a nonzero estimate"
    );
    // No hardcoded byte assertion against a pre-existing declared budget (L1's §5 cell has no
    // byte figure to check, unlike L4) — this measurement's job is to REPORT the figure, which
    // `docs/spec/Language-Retention-Policy.md` §5 records from a `--nocapture` run of this test.
    eprintln!(
        "synthetic_load_at_certified_cap_reports_estimated_bytes: cap={cap} \
         retained_estimate_bytes={retained_estimate} per_cert_avg={}",
        retained_estimate / cap
    );
}
