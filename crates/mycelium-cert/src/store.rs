//! **Mode-gated, capped, content-addressed certificate store** (DN-142 §4.2; P1-Q2 handle-plus-sink
//! architecture; `docs/spec/Language-Retention-Policy.md` §5 P4-Q1 dual caps).
//!
//! The handle-plus-sink design closes the `ModeGatedSwapEngine` cert-discard gap *without* widening
//! [`crate::SwapEngine`](mycelium_interp::SwapEngine): the certificate **body** goes here (a small,
//! capped, content-addressed store), and the **handle** (its [`ContentHash`]) is what rides
//! [`Meta::cert`](mycelium_core::Meta::cert) — self-computing (the same hash function this module
//! exposes as [`cert_content_hash`]), so a `Meta.cert` handle is meaningful whether or not any
//! particular [`CertStore`] instance actually retained the body.
//!
//! **Capped by construction (G-8 — no unbounded accumulator before caps exist).** [`CertStore`]
//! never grows past [`declared_cert_handle_cap`] for its mode: exceeding the cap evicts the oldest
//! handle (`drop_oldest`, the `LanguageRetentionPolicy` §5 `on_overflow` shape) and increments a
//! never-silent drop counter ([`CertStore::dropped`] — the EXPLAIN-of-drop discipline, §8 of that
//! spec) rather than growing without bound.

use std::collections::{BTreeMap, VecDeque};

use mycelium_core::{CertMode, ContentHash};

use crate::SwapCertificate;

/// The `LanguageRetentionPolicy` §5 **Declared placeholder** cert-handle cap for `mode` (P4-Q1).
///
/// `Fast` = `0` (the steer's literal number — nothing is retained; `Fast` does not even emit a
/// certificate, so this is a floor, not a design choice this module makes). `Certified` = `256`
/// (also the steer's literal number).
///
/// **`Balanced`'s cap is genuinely unspecified by the steer** — `Language-Retention-Policy.md` §5
/// marks it FLAGGED, not interpolated (its table has a literal "not specified by the steer —
/// FLAGGED" cell for every `balanced` column). This function's own judgment call for W-A
/// (`Declared`, flagged here and in the wave report — not a steered number): reuse `Certified`'s
/// cap rather than either inventing a distinct figure or leaving `Balanced` uncapped (which would
/// violate G-8). Revisit once the Phase-2 sizing pass (`Declared` → `Empirical`) lands.
#[must_use]
pub fn declared_cert_handle_cap(mode: CertMode) -> usize {
    match mode {
        CertMode::Fast => 0,
        CertMode::Balanced | CertMode::Certified => 256,
    }
}

/// The content address of a certificate **body** (ADR-003) — canonical JSON bytes over BLAKE3, the
/// same small local framing style [`mycelium_diag::Diag::content_hash`] uses (KC-3: no shared
/// hashing dependency is added between these crates; each carries its own minimal framing). This is
/// the single source of truth for a certificate's handle: [`CertStore::insert`] uses it as the map
/// key, and `mycelium-cert::mode::gate_swap` uses it to set `Meta.cert` — so the two always agree
/// without the store needing to be present at the call site that sets the handle.
#[must_use]
pub fn cert_content_hash(cert: &SwapCertificate) -> ContentHash {
    let bytes = serde_json::to_vec(cert).expect("SwapCertificate always serializes");
    let mut h = blake3::Hasher::new();
    // Domain separation, length-prefixed (mirrors `mycelium-diag`'s local `Canon`): a certificate
    // body's hash can never collide with a hash computed for a different record kind that happens
    // to share byte content.
    h.update(b"mycelium.cert.store.v1");
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(&bytes);
    let hex = h.finalize().to_hex();
    ContentHash::from_parts("blake3", hex.as_str()).expect("blake3 hex is always a valid digest")
}

/// A mode-gated, capped, content-addressed store for certificate **bodies** (DN-142 §4.2). The
/// handle (a [`ContentHash`], via [`cert_content_hash`]) is what rides `Meta.cert`; the body lives
/// here, addressable by that same hash.
#[derive(Debug, Default)]
pub struct CertStore {
    bodies: BTreeMap<ContentHash, SwapCertificate>,
    /// Insertion order, for `drop_oldest` eviction — a plain ring, not a growing log (G-8).
    order: VecDeque<ContentHash>,
    /// The never-silent drop counter (EXPLAIN-of-drop; `LanguageRetentionPolicy` §8): how many cert
    /// bodies this store has evicted under cap pressure since construction.
    dropped: u64,
}

impl CertStore {
    /// A fresh, empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `cert`'s body under `mode`'s Declared cap ([`declared_cert_handle_cap`]).
    ///
    /// Returns the handle iff `mode` retains anything at all — `Fast`'s cap is `0`, so this inserts
    /// nothing and returns `None` (mirroring `Fast` emitting no certificate at all; never a
    /// fabricated handle to a body that was never stored). A re-insert of an already-stored cert
    /// (identical content hash) is a no-op that still returns the existing handle: idempotent, and
    /// it never double-counts a drop or reorders the ring for a cert that was already present.
    pub fn insert(&mut self, mode: CertMode, cert: &SwapCertificate) -> Option<ContentHash> {
        let cap = declared_cert_handle_cap(mode);
        if cap == 0 {
            return None;
        }
        let handle = cert_content_hash(cert);
        if self.bodies.contains_key(&handle) {
            return Some(handle);
        }
        // `drop_oldest` (LanguageRetentionPolicy §5 `on_overflow`): evict from the front of the
        // ring until there is room, incrementing the never-silent drop counter per eviction.
        while self.bodies.len() >= cap {
            let Some(oldest) = self.order.pop_front() else {
                break; // Defensive: `order` and `bodies` are kept in lockstep by construction.
            };
            self.bodies.remove(&oldest);
            self.dropped += 1;
        }
        self.bodies.insert(handle.clone(), cert.clone());
        self.order.push_back(handle.clone());
        Some(handle)
    }

    /// The certificate body for `handle`, if this store still retains it (never guaranteed — a
    /// handle can outlive its body under cap pressure; that is the point of a capped store, and is
    /// reported via [`Self::dropped`], not hidden).
    #[must_use]
    pub fn get(&self, handle: &ContentHash) -> Option<&SwapCertificate> {
        self.bodies.get(handle)
    }

    /// How many certificate bodies this store currently retains.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bodies.len()
    }

    /// Whether this store currently retains any certificate bodies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }

    /// The never-silent drop counter (EXPLAIN-of-drop; `LanguageRetentionPolicy` §8): how many
    /// certificate bodies this store has evicted under cap pressure since construction. Never
    /// silently reset or hidden — the store's whole eviction history is one integer read away.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}
