//! `mycelium-cert::store` — the mode-gated, capped, content-addressed certificate store (DN-142
//! §4.2; P1-Q2 handle-plus-sink; `docs/spec/Language-Retention-Policy.md` §5 P4-Q1 dual caps).
//!
//! Three families: cap boundary + eviction (`drop_oldest`), never-silent drop accounting
//! (EXPLAIN-of-drop), and `fast`-mode zero-retention.

use mycelium_cert::{cert_content_hash, declared_cert_handle_cap, CertStore, SwapCertificate};
use mycelium_core::{
    Bound, BoundBasis, BoundKind, CertMode, ContentHash, NormKind, Repr, ScalarKind,
};

/// A `Bounded` certificate parameterized by `eps` — distinct `eps` values produce distinct
/// content hashes (the store's key), so a sweep of `eps` gives a sweep of distinct cert bodies.
fn cert_at(eps: f64) -> SwapCertificate {
    SwapCertificate::Bounded {
        src: Repr::Dense {
            dim: 1,
            dtype: ScalarKind::F32,
        },
        target: Repr::Dense {
            dim: 1,
            dtype: ScalarKind::Bf16,
        },
        policy_used: ContentHash::parse("blake3:store_test_policy").unwrap(),
        bound: Bound {
            kind: BoundKind::Error {
                eps,
                norm: NormKind::L2,
            },
            basis: BoundBasis::ProvenThm {
                citation: "test".to_owned(),
            },
        },
    }
}

// ---------- fast-mode zero-retention ----------

/// `LanguageRetentionPolicy` §5: `fast`'s cap is `0` — `insert` must be a no-op, never a handle to
/// a body that was not actually retained (G2).
#[test]
fn fast_mode_retains_nothing() {
    assert_eq!(declared_cert_handle_cap(CertMode::Fast), 0);
    let mut store = CertStore::new();
    let handle = store.insert(CertMode::Fast, &cert_at(0.1));
    assert!(handle.is_none(), "fast must not retain anything");
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert_eq!(
        store.dropped(),
        0,
        "nothing was ever inserted, so nothing was ever dropped"
    );
}

// ---------- cap boundary + drop_oldest eviction ----------

/// The `Certified` cap is exactly the steer's literal `256` (P4-Q1). At the boundary nothing is
/// evicted; one insert past it evicts exactly the oldest handle and counts exactly one drop.
#[test]
fn certified_cap_boundary_evicts_oldest_and_counts_the_drop() {
    let cap = declared_cert_handle_cap(CertMode::Certified);
    assert_eq!(cap, 256, "the steer's literal Certified cap (P4-Q1)");

    let mut store = CertStore::new();
    let mut handles = Vec::with_capacity(cap);
    for i in 0..cap {
        let h = store
            .insert(CertMode::Certified, &cert_at(0.001 * (i as f64 + 1.0)))
            .expect("certified mode retains");
        handles.push(h);
    }
    assert_eq!(store.len(), cap);
    assert_eq!(
        store.dropped(),
        0,
        "no drop yet — exactly at the cap, not over it"
    );
    assert!(
        store.get(&handles[0]).is_some(),
        "the oldest handle is still present at the boundary"
    );

    // One more insert must evict exactly the oldest and count exactly one drop.
    let overflow = store
        .insert(CertMode::Certified, &cert_at(0.001 * (cap as f64 + 1.0)))
        .expect("certified mode retains");
    assert_eq!(store.len(), cap, "the store never grows past the cap (G-8)");
    assert_eq!(
        store.dropped(),
        1,
        "exactly one eviction — never-silent drop accounting"
    );
    assert!(
        store.get(&handles[0]).is_none(),
        "the oldest handle was evicted (drop_oldest)"
    );
    assert!(
        store.get(&handles[1]).is_some(),
        "the second-oldest survives"
    );
    assert!(
        store.get(&overflow).is_some(),
        "the newly-inserted cert is retained"
    );
}

/// A second overflow evicts the *new* oldest and the drop counter keeps accumulating — the ring
/// discipline holds under repeated pressure, not just a single overflow.
#[test]
fn repeated_overflow_keeps_evicting_the_oldest_and_accumulating_drops() {
    let cap = declared_cert_handle_cap(CertMode::Certified);
    let mut store = CertStore::new();
    let mut handles = Vec::with_capacity(cap + 3);
    for i in 0..(cap + 3) {
        let h = store
            .insert(CertMode::Certified, &cert_at(0.001 * (i as f64 + 1.0)))
            .unwrap();
        handles.push(h);
    }
    assert_eq!(store.len(), cap, "still capped after 3 overflows");
    assert_eq!(
        store.dropped(),
        3,
        "one drop per overflow insert, accumulated"
    );
    // The three oldest are gone; the rest survive.
    assert!(store.get(&handles[0]).is_none());
    assert!(store.get(&handles[1]).is_none());
    assert!(store.get(&handles[2]).is_none());
    assert!(store.get(&handles[3]).is_some());
    assert!(store.get(handles.last().unwrap()).is_some());
}

/// Re-inserting an identical cert body (same content hash) is a no-op: it does not grow the store,
/// does not reorder the ring, and does not count as a drop.
#[test]
fn reinserting_an_identical_cert_is_a_no_op_and_never_counts_as_a_drop() {
    let mut store = CertStore::new();
    let cert = cert_at(0.5);
    let h1 = store.insert(CertMode::Certified, &cert).unwrap();
    let h2 = store.insert(CertMode::Certified, &cert).unwrap();
    assert_eq!(
        h1, h2,
        "an identical cert body re-inserts to the same handle (content-addressed)"
    );
    assert_eq!(store.len(), 1);
    assert_eq!(store.dropped(), 0);
}

/// The store's key always agrees with the standalone [`cert_content_hash`] function — the same one
/// `Meta.cert` (mycelium-core) is populated with, independent of any store instance. DRY: the two
/// can never drift apart.
#[test]
fn handle_matches_the_standalone_content_hash_function() {
    let cert = cert_at(0.25);
    let mut store = CertStore::new();
    let handle = store.insert(CertMode::Certified, &cert).unwrap();
    assert_eq!(handle, cert_content_hash(&cert));
}

// ---------- balanced mode retains too (under its own — documented judgment-call — cap) ----------

/// `Balanced`'s cap is a documented W-A judgment call (`Language-Retention-Policy.md` §5 flags it
/// unspecified by the steer) — this crate reuses `Certified`'s number. Assert that choice holds and
/// that `Balanced` does retain (unlike `Fast`).
#[test]
fn balanced_retains_under_its_own_cap() {
    assert_eq!(
        declared_cert_handle_cap(CertMode::Balanced),
        declared_cert_handle_cap(CertMode::Certified),
        "documented W-A judgment call: Balanced reuses Certified's cap (genuinely unspecified by \
         the steer — Language-Retention-Policy.md §5)"
    );
    let mut store = CertStore::new();
    let handle = store.insert(CertMode::Balanced, &cert_at(0.3));
    assert!(handle.is_some());
    assert_eq!(store.len(), 1);
    assert_eq!(store.dropped(), 0);
}
