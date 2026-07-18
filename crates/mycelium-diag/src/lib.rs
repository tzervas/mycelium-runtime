//! `mycelium-diag` — the canonical RFC-0013 structured-diagnostic record types.
//!
//! # Why this crate exists (maintainer decision, 2026-06-18)
//!
//! RFC-0013/RFC-0014 concepts (the structured diagnostic + the recovery bridge) were scattered
//! across `mycelium-check`/`mycelium-l1`/`mycelium-interp`/`mycelium-lsp`. The Phase-5 Tier-A wave
//! (M-510/M-520) needs **one** consolidated reference for the diagnostic record that
//! `std.diag` projects, `std.recover` carries, and `std.testing` records a `Fail` on. Per the
//! maintainer's resolved FLAG (scaffold decision #1), that canonical record is **extracted into
//! this small kernel crate** rather than homed inside `mycelium-std-diag` — a deliberate, bounded
//! growth of the trusted base so the type has a single owner below the std layer. `mycelium-std-diag`
//! re-exports and ergonomically wraps these types (KC-3); it does not redefine them.
//!
//! # Honesty crux (RFC-0013 I1)
//!
//! A `Diag` is **additive over an explicit error**: it presents a failure, it never *is* the
//! failure's control flow. Presentation never gates propagation — there is no severity, note, or
//! locus that makes an underlying error *not* surface. Construction is **total**: a missing locus is
//! [`None`] (explicit), never a fabricated zero (G2).
//!
//! Design spec: `docs/spec/stdlib/diag.md`; RFC-0013; task M-510, issue #151.
//!
//! # Dual projection (G11 / RFC-0013 I3)
//!
//! A `Diag` has one canonical truth; human and JSON are two renderers of it.
//! - [`Diag::human`] — human-readable view; carries the content id.
//! - [`Diag::machine`] — lossless JSON machine record with embedded `id`
//!   (round-trips via [`Diag::from_json`]).
//! - [`Diag::content_hash`] — deterministic BLAKE3 over the canonical fields *sans presentation*
//!   (ADR-003): identity is the record, not how it is shown. Presentation-invariant.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub use mycelium_core::{CertMode, ContentHash, GuaranteeStrength};

// ─── A local injective BLAKE3 framing ─────────────────────────────────────────────────────────────
//
// Mirrors the pattern in `mycelium-lsp/src/diagnostics/record.rs` and
// `mycelium-core/src/content.rs` (KC-3 — no kernel dep added; the kernel crate itself also carries
// this local framing for the tooling layer).

/// A canonical, injective byte encoder for content-addressing a `Diag`. Length-prefixed blobs so no
/// two distinct records share an encoding.
struct Canon {
    h: blake3::Hasher,
}

impl Canon {
    fn new(domain: &str) -> Self {
        let mut c = Canon {
            h: blake3::Hasher::new(),
        };
        // Domain separation: hashing the domain string first ensures diag hashes can never collide
        // with hashes of other record kinds that share the same field layout.
        c.blob(domain.as_bytes());
        c
    }

    fn blob(&mut self, bytes: &[u8]) {
        self.h.update(&(bytes.len() as u64).to_le_bytes());
        self.h.update(bytes);
    }

    fn str(&mut self, s: &str) {
        self.blob(s.as_bytes());
    }

    /// Encode `None` and `Some("")` as distinct byte sequences (tagged).
    fn opt(&mut self, s: Option<&str>) {
        match s {
            None => {
                self.h.update(&[0u8]);
            }
            Some(v) => {
                self.h.update(&[1u8]);
                self.str(v);
            }
        }
    }

    fn finish(self) -> ContentHash {
        let hex = self.h.finalize().to_hex();
        // BLAKE3 hex is always 64 lowercase hex chars — a well-formed digest.
        ContentHash::from_parts("blake3", hex.as_str())
            .expect("blake3 hex is always a valid digest")
    }
}

// ─── Severity ─────────────────────────────────────────────────────────────────────────────────────

/// Graded diagnostic severity (RFC-0013 §4.1). A **typed** distinction — never a stringly-typed
/// level. Presentation severity **never gates propagation** (I1): a `Warn` never silently becomes a
/// pass, and an `Error` severity does not itself halt anything — it annotates an already-explicit
/// error.
///
/// Ordered `Debug < Info < Warn < Error` (weakest-to-strongest). The ordering is purely for
/// comparisons and aggregation; it does **not** gate propagation (I1).
/// `#[non_exhaustive]`: a future severity grade may be added without a breaking change — an external
/// exhaustive `match` must carry a `_` arm (M-644; additive — no variant removed; the `Ord` order and
/// [`Severity::ALL`] are preserved). In-crate matches and `ALL` already name every variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Severity {
    /// A debug-grade diagnostic (lowest severity).
    Debug,
    /// An informational diagnostic.
    Info,
    /// A warning-grade diagnostic.
    Warn,
    /// An error-grade diagnostic (highest severity).
    Error,
}

impl Severity {
    /// All severities, ordered weakest-to-strongest (`Debug < Info < Warn < Error`).
    pub const ALL: [Severity; 4] = [
        Severity::Debug,
        Severity::Info,
        Severity::Warn,
        Severity::Error,
    ];

    /// The canonical name used in human/machine output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warn => "warn",
            Severity::Info => "info",
            Severity::Debug => "debug",
        }
    }
}

// ─── Code ─────────────────────────────────────────────────────────────────────────────────────────

/// A stable diagnostic code / error class (RFC-0013 §4.2). Closed for the common kernel cases with
/// an explicit [`Code::Other`] escape hatch — never a stringly-typed free-for-all on the common
/// path. The set may be widened additively (via new variants) as the spec's class registry grows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum Code {
    /// A value fell outside its declared range/domain.
    OutOfRange,
    /// A declared, bounded effect budget was exhausted (RFC-0014 I3/I4).
    Budget,
    /// A content-hash / identity mismatch (ADR-003).
    HashMismatch,
    /// An open-coded class identified by a stable string (the registry escape hatch).
    Other(String),
}

impl Code {
    /// The canonical code name for use in human/machine output.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Code::OutOfRange => "OutOfRange",
            Code::Budget => "Budget",
            Code::HashMismatch => "HashMismatch",
            Code::Other(s) => s.as_str(),
        }
    }
}

// ─── Locus ────────────────────────────────────────────────────────────────────────────────────────

/// A source locus — *where* a diagnostic points (RFC-0013 §4.2). All fields are optional: an absent
/// locus stays [`None`] on the [`Diag`], and an absent span/line stays `None` here — **never** a
/// fabricated zero (G2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Locus {
    /// Source path/name, if known.
    pub source: Option<String>,
    /// 1-based line, if known.
    pub line: Option<u32>,
    /// 1-based column, if known.
    pub column: Option<u32>,
}

// ─── Trace ────────────────────────────────────────────────────────────────────────────────────────

/// An ordered diagnostic trace — the chain of frames/notes that led to the failure (RFC-0013 §4.3).
/// A thin newtype over the frame list so it can grow a richer frame model without breaking callers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Trace {
    /// Trace frames, outermost-first.
    pub frames: Vec<String>,
}

impl Trace {
    /// The empty trace (explicit absence — not a fabricated frame).
    #[must_use]
    pub fn empty() -> Self {
        Self { frames: Vec::new() }
    }

    /// Push a frame, returning the extended trace (value-semantic).
    #[must_use]
    pub fn with_frame(mut self, frame: impl Into<String>) -> Self {
        self.frames.push(frame.into());
        self
    }
}

// ─── First-fault envelope (RFC-0013 Amendment A1 §10, Draft — captured 2026-07-18) ─────────────────
//
// Amendment A1 (§10.7) is explicit: "Nothing in this amendment lands as code with this capture" —
// this wave (W-A, `PROGRAM-HANDOFF-DESIGN-STEER-2026-07-17.md` §5) is that landing. The envelope is
// an ADDITIVE, OPTIONAL extension of `Diag` (I1): a `Diag` built without one behaves exactly as
// before this amendment (§10.7's own stability requirement) — see the `content_hash`/`human`
// backward-compatibility tests in `src/tests.rs`.

/// Which stage emitted the record (RFC-0013 Amendment A1 §10.2) — a closed enum, no escape hatch:
/// the amendment names exactly these five phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// The compile phase.
    Compile,
    /// The check (type-check) phase.
    Check,
    /// The runtime (evaluation) phase.
    Runtime,
    /// The transpile phase.
    Transpile,
    /// The packaging (spore build) phase.
    Packaging,
}

impl Phase {
    /// The canonical name for use in human/machine output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Compile => "compile",
            Phase::Check => "check",
            Phase::Runtime => "runtime",
            Phase::Transpile => "transpile",
            Phase::Packaging => "packaging",
        }
    }
}

/// The junction-kind catalog (RFC-0013 Amendment A1 §10.3) — the complete 13-entry Localize-1
/// attachment list, closed for the common cases with an [`Other`](SiteKind::Other) escape hatch,
/// mirroring [`Code`]'s shape (`crates/mycelium-diag/src/lib.rs` `Code`, above).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum SiteKind {
    /// Selection resolution to a `PolicyRef` (check).
    PolicyResolve,
    /// Illegal `Repr` pair (check).
    LegalPairRefuse,
    /// Cross-paradigm without a written `swap` (check).
    MissingConversion,
    /// A total type over a partial regime (check).
    RegimeTypeLie,
    /// Swap `Ok`/`Err` / out-of-range (runtime).
    SwapExec,
    /// Cert `Validated`/`Refuted`/`NotValidated` — first emitter site is `ModeGatedSwapEngine`'s
    /// `SwapEngine` impl, the `NotValidated` branch (runtime; `mycelium-cert/src/mode.rs`).
    SwapCheck,
    /// Export / certified demand / `Exact` partition (check/runtime).
    MeetBoundary,
    /// Dynamic meet of tagged values (runtime).
    GradeMeet,
    /// Airlock pass/fail (runtime).
    SealRemint,
    /// Mode × grade refuse without a seal (check).
    ModeFirewall,
    /// Illegal strengthen (check).
    GradeAnnotation,
    /// First bad import edge (check).
    ImportFirstEdge,
    /// First poison / residual (transpile).
    TranspileGap,
    /// An open-coded site kind identified by a stable string (the registry escape hatch).
    Other(String),
}

impl SiteKind {
    /// The canonical `site_kind` name (RFC-0013 Amendment A1 §10.3 table) for human/machine output.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            SiteKind::PolicyResolve => "policy_resolve",
            SiteKind::LegalPairRefuse => "legal_pair_refuse",
            SiteKind::MissingConversion => "missing_conversion",
            SiteKind::RegimeTypeLie => "regime_type_lie",
            SiteKind::SwapExec => "swap_exec",
            SiteKind::SwapCheck => "swap_check",
            SiteKind::MeetBoundary => "meet_boundary",
            SiteKind::GradeMeet => "grade_meet",
            SiteKind::SealRemint => "seal_remint",
            SiteKind::ModeFirewall => "mode_firewall",
            SiteKind::GradeAnnotation => "grade_annotation",
            SiteKind::ImportFirstEdge => "import_first_edge",
            SiteKind::TranspileGap => "transpile_gap",
            SiteKind::Other(s) => s.as_str(),
        }
    }
}

/// What a junction concluded (RFC-0013 Amendment A1 §10.2) — closed for the common cases named in
/// the amendment's prose (`refuse | seal_fail | not_validated | resolved | fallback | remint |
/// candidate`) with an [`Other`](Decision::Other) escape hatch, mirroring [`Code`]'s shape.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum Decision {
    /// The junction refused.
    Refuse,
    /// A seal (airlock) failed.
    SealFail,
    /// The check did not validate (mirrors [`crate`]-consumer `CheckVerdict::NotValidated`, e.g.
    /// `mycelium-cert`'s checker — this crate does not depend on that one, KC-3).
    NotValidated,
    /// Resolution succeeded.
    Resolved,
    /// A fallback path was taken.
    Fallback,
    /// A remint (grade re-basing) occurred.
    Remint,
    /// A non-auto-applied candidate was produced (never silently applied — X11 posture).
    Candidate,
    /// An open-coded decision identified by a stable string (the registry escape hatch).
    Other(String),
}

impl Decision {
    /// The canonical decision name for human/machine output.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Decision::Refuse => "refuse",
            Decision::SealFail => "seal_fail",
            Decision::NotValidated => "not_validated",
            Decision::Resolved => "resolved",
            Decision::Fallback => "fallback",
            Decision::Remint => "remint",
            Decision::Candidate => "candidate",
            Decision::Other(s) => s.as_str(),
        }
    }
}

/// A stable identifier for one fault **instance** (RFC-0013 Amendment A1 §10.2).
///
/// **Judgment call, flagged (not a ratified decision — G2/VR-5).** The amendment leaves the exact
/// shape genuinely open: "whether `event_id` coincides with `Diag::content_hash()` … or is a
/// separate per-occurrence counter/nonce is left to the Phase-2 implementation; flagged, not decided
/// here" (§10.2). This crate's W-A choice is to commit to **neither** shape: `EventId` is an opaque,
/// caller-supplied string. Nothing in this crate auto-generates one (a global counter/nonce would be
/// hidden mutable state this crate does not want to own; a content-hash-derived id is available to
/// any caller via [`EventId::from_content_hash`] for callers that want that shape). This keeps the
/// question open exactly as the amendment left it, rather than silently picking a side.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

impl EventId {
    /// An `EventId` from a caller-supplied opaque string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// An `EventId` derived from a [`ContentHash`] — the "coincides with `content_hash()`" shape the
    /// amendment names as one option (not the only one; see the type's own doc).
    #[must_use]
    pub fn from_content_hash(hash: &ContentHash) -> Self {
        Self(hash.as_str().to_owned())
    }

    /// The opaque string identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Input grade(s) and the result grade, if any (RFC-0013 Amendment A1 §10.2) — reporting fields
/// only: they report what the junction already computed and are **never** themselves an upgrade
/// path (VR-5; §10.4 rule 3).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Grades {
    /// The input grade(s) the junction consumed.
    pub input: Vec<GuaranteeStrength>,
    /// The result grade, if the junction produced one.
    pub output: Option<GuaranteeStrength>,
}

/// The first-fault envelope (RFC-0013 Amendment A1 §10.2) — the fields a first-fault junction needs
/// to answer *where / how / why* in one hop (DESIGN-03 §3.2). Additive over the base [`Diag`]
/// fields (I1): attaching an envelope never changes `severity`/`code`/`message`/`locus`/`trace`/
/// `notes`, and every field here **reports** what the emitting junction already decided — this
/// struct never itself decides anything (§10.7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstFaultEnvelope {
    /// A stable identifier for this fault instance (shape genuinely open — see [`EventId`]).
    pub event_id: EventId,
    /// Which stage emitted the record.
    pub phase: Phase,
    /// The junction kind (the 13-entry catalog, §10.3).
    pub site_kind: SiteKind,
    /// What the junction concluded.
    pub decision: Decision,
    /// The registry machine code for this record (opaque `Declared` string in v0 — DN-22 has not
    /// ratified the compact-code shape yet; never fabricated as a ratified code).
    pub how: String,
    /// Input grade(s) and the result grade, if any (never upgraded by this record — VR-5).
    pub grades: Grades,
    /// The content hash of the selection policy that shaped this decision, if any.
    pub policy_ref: Option<ContentHash>,
    /// The active `CertMode` at emission time (always present).
    pub cert_mode: CertMode,
    /// Matrix row id / predicate id / cert hash the decision rests on, or absent.
    pub basis_ref: Option<String>,
    /// The fault this record is downstream of, if any (blame-style causality — §10.4).
    pub parent_event: Option<EventId>,
    /// The record this fault directly caused, if any (§10.4).
    pub child_cause: Option<EventId>,
}

impl FirstFaultEnvelope {
    /// A total constructor for the mandatory fields (`event_id`/`phase`/`site_kind`/`decision`/
    /// `how`/`cert_mode`); every optional field starts explicitly absent (`grades` empty/`None`,
    /// `policy_ref`/`basis_ref`/`parent_event`/`child_cause` all `None`) — never a fabricated
    /// placeholder (G2). Use the `with_*` builders to attach the optional fields.
    #[must_use]
    pub fn new(
        event_id: EventId,
        phase: Phase,
        site_kind: SiteKind,
        decision: Decision,
        how: impl Into<String>,
        cert_mode: CertMode,
    ) -> Self {
        Self {
            event_id,
            phase,
            site_kind,
            decision,
            how: how.into(),
            grades: Grades::default(),
            policy_ref: None,
            cert_mode,
            basis_ref: None,
            parent_event: None,
            child_cause: None,
        }
    }

    /// Attach the input/output grades (value-semantic builder).
    #[must_use]
    pub fn with_grades(mut self, grades: Grades) -> Self {
        self.grades = grades;
        self
    }

    /// Attach the shaping policy's content hash (§10.4 rule 5 — the pack-01 catalog/resolve
    /// mechanism is the only populating source; this method does not itself resolve one).
    #[must_use]
    pub fn with_policy_ref(mut self, policy_ref: ContentHash) -> Self {
        self.policy_ref = Some(policy_ref);
        self
    }

    /// Attach the basis reference (matrix row id / predicate id / cert hash).
    #[must_use]
    pub fn with_basis_ref(mut self, basis_ref: impl Into<String>) -> Self {
        self.basis_ref = Some(basis_ref.into());
        self
    }

    /// Attach the parent event this record is downstream of (§10.4 rule 2).
    #[must_use]
    pub fn with_parent_event(mut self, parent: EventId) -> Self {
        self.parent_event = Some(parent);
        self
    }

    /// Attach the child record this fault directly caused (§10.4 rule 1).
    #[must_use]
    pub fn with_child_cause(mut self, child: EventId) -> Self {
        self.child_cause = Some(child);
        self
    }
}

// ─── Diag ─────────────────────────────────────────────────────────────────────────────────────────

/// A structured diagnostic record (RFC-0013 §4.1): a content-addressable value over an
/// already-emitted explicit error. Identity is the record *sans presentation* (ADR-003) —
/// [`Diag::content_hash`] is a deterministic BLAKE3 over the canonical fields, presentation-
/// invariant so the human and JSON projections share one identity (I3). Builders are total;
/// a missing locus is [`None`].
///
/// `envelope` (RFC-0013 Amendment A1 §10) is an **additive, optional** extension (I1): a `Diag`
/// built without one is byte-identical (content hash and `human()` text) to a pre-amendment `Diag`
/// — see `src/tests.rs` for the backward-compatibility goldens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diag {
    /// The graded severity (typed; never gates propagation — I1).
    pub severity: Severity,
    /// The diagnostic code / error class.
    pub code: Code,
    /// The human-readable message.
    pub message: String,
    /// Where the diagnostic points, if known (explicit `None` when absent).
    pub locus: Option<Locus>,
    /// The diagnostic trace.
    pub trace: Trace,
    /// Free-form notes (EXPLAIN payload, G11).
    pub notes: Vec<String>,
    /// The first-fault envelope (RFC-0013 Amendment A1 §10), if this record was emitted at a named
    /// junction (`site_kind`). `None` for every diagnostic that predates/does not use the amendment
    /// — additive, never substitutive (I1).
    pub envelope: Option<FirstFaultEnvelope>,
}

/// Render a locus as `source:line:col` (whatever subset is known), or the explicit unknown marker
/// `"?"` for an absent locus — used by [`Diag::first_fault_line`]. A small standalone helper (not a
/// refactor of [`Diag::human`]'s own inline locus rendering) to keep this change's blast radius off
/// `human()`'s already-tested exact output.
fn render_where(locus: &Option<Locus>) -> String {
    let Some(l) = locus else {
        return "?".to_owned();
    };
    let mut loc = String::new();
    if let Some(s) = &l.source {
        loc.push_str(s);
    }
    if let Some(line) = l.line {
        if !loc.is_empty() {
            loc.push(':');
        }
        loc.push_str(&line.to_string());
        if let Some(col) = l.column {
            loc.push(':');
            loc.push_str(&col.to_string());
        }
    }
    if loc.is_empty() {
        "?".to_owned()
    } else {
        loc
    }
}

impl Diag {
    // ── Builders (total; a missing field is explicit absence, never a fabricated zero) ──────────

    /// Build an `Error`-severity diagnostic with the given code (total builder).
    #[must_use]
    pub fn error(code: Code) -> Self {
        Self::with_severity(Severity::Error, code)
    }

    /// Build a `Warn`-severity diagnostic with the given code (total builder).
    #[must_use]
    pub fn warn(code: Code) -> Self {
        Self::with_severity(Severity::Warn, code)
    }

    /// Build an `Info`-severity diagnostic with the given code (total builder).
    #[must_use]
    pub fn info(code: Code) -> Self {
        Self::with_severity(Severity::Info, code)
    }

    /// The common total builder behind [`Self::error`]/[`Self::warn`]/[`Self::info`].
    #[must_use]
    pub fn with_severity(severity: Severity, code: Code) -> Self {
        Self {
            severity,
            code,
            message: String::new(),
            locus: None,
            trace: Trace::empty(),
            notes: Vec::new(),
            envelope: None,
        }
    }

    /// Set the human-readable message (value-semantic builder).
    #[must_use]
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Attach a source locus (explicit; absence stays `None` — never a fabricated zero, G2).
    #[must_use]
    pub fn at(mut self, locus: Locus) -> Self {
        self.locus = Some(locus);
        self
    }

    /// Attach a note (EXPLAIN payload).
    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }

    /// Replace the trace (value-semantic builder).
    #[must_use]
    pub fn trace(mut self, trace: Trace) -> Self {
        self.trace = trace;
        self
    }

    /// Attach a [`FirstFaultEnvelope`] (RFC-0013 Amendment A1 §10) — additive only (I1): this never
    /// changes `severity`/`code`/`message`/`locus`/`trace`/`notes`.
    #[must_use]
    pub fn with_envelope(mut self, envelope: FirstFaultEnvelope) -> Self {
        self.envelope = Some(envelope);
        self
    }

    // ── Field accessors ─────────────────────────────────────────────────────────────────────────

    /// The typed severity (a `Warn` never silently becomes a pass — I1).
    #[must_use]
    pub fn severity(&self) -> Severity {
        self.severity
    }

    /// The diagnostic code / error class.
    #[must_use]
    pub fn code(&self) -> &Code {
        &self.code
    }

    /// The attached [`FirstFaultEnvelope`] (RFC-0013 Amendment A1 §10), if any.
    #[must_use]
    pub fn envelope(&self) -> Option<&FirstFaultEnvelope> {
        self.envelope.as_ref()
    }

    // ── First-fault one-liner (RFC-0013 Amendment A1 §10 / DESIGN-03 §3.2) ─────────────────────

    /// The **lean first-fault one-liner**: `where · site_kind · decision`, in one hop — no tree dig
    /// (N6/N9, DESIGN-03 §3.2). `None` for an envelope-less `Diag`: there is no `site_kind`/
    /// `decision` to render, and this method never fabricates one (G2) — a caller with no envelope
    /// reads [`Diag::human`]/[`Diag::machine`] instead, exactly as before this amendment (I1).
    ///
    /// `where` renders the base `Diag`'s `locus` (independent of the envelope) as `source:line:col`
    /// (whatever subset is known), or the explicit unknown marker `"?"` when no locus is attached —
    /// never a fabricated position (G2).
    ///
    /// # Guarantee: `Exact`
    /// Pure value transform; no approximation. (RFC-0016 §4.5, VR-5)
    #[must_use]
    pub fn first_fault_line(&self) -> Option<String> {
        let env = self.envelope.as_ref()?;
        Some(format!(
            "{} · {} · {}",
            render_where(&self.locus),
            env.site_kind.as_str(),
            env.decision.as_str()
        ))
    }

    // ── Content address (ADR-003 / RFC-0013 I3) ─────────────────────────────────────────────────

    /// The **content address** of this diagnostic (RFC-0013 §4.3; ADR-003) — a deterministic BLAKE3
    /// over the **canonical fields** (severity, code, message, locus, trace, notes), excluding the
    /// rendered presentation (the formatted human string and JSON output are not hash inputs).
    /// Presentation-invariant: the same `Diag` content always hashes the same, so the human
    /// and JSON projections share one identity (I3).
    ///
    /// # Guarantee: `Exact`
    /// Pure value transform; no approximation. (RFC-0016 §4.5, VR-5)
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut c = Canon::new("mycelium.diag.v1");
        c.str(self.severity.as_str());
        c.str(self.code.as_str());
        c.str(&self.message);
        // Locus: tag absence vs. presence distinctly (G2 — `None` ≠ `Some(Locus::default())`).
        match &self.locus {
            None => {
                c.h.update(&[0u8]);
            }
            Some(l) => {
                c.h.update(&[1u8]);
                c.opt(l.source.as_deref());
                match l.line {
                    None => {
                        c.h.update(&[0u8]);
                    }
                    Some(n) => {
                        c.h.update(&[1u8]);
                        c.h.update(&n.to_le_bytes());
                    }
                }
                match l.column {
                    None => {
                        c.h.update(&[0u8]);
                    }
                    Some(n) => {
                        c.h.update(&[1u8]);
                        c.h.update(&n.to_le_bytes());
                    }
                }
            }
        }
        // Trace frames (length-prefixed list so an empty trace ≠ a one-element trace with "").
        c.h.update(&(self.trace.frames.len() as u64).to_le_bytes());
        for frame in &self.trace.frames {
            c.str(frame);
        }
        // Notes (length-prefixed list).
        c.h.update(&(self.notes.len() as u64).to_le_bytes());
        for note in &self.notes {
            c.str(note);
        }
        // Envelope (RFC-0013 Amendment A1 §10): fed into the hash ONLY when present, and nothing at
        // all when absent — so an envelope-less `Diag`'s hash is byte-identical to what this method
        // computed before this amendment (backward-compatibility golden in `src/tests.rs`), while an
        // attached envelope is fully identity-bearing (two Diags differing only in `site_kind` or
        // `decision` must not collide).
        if let Some(env) = &self.envelope {
            c.h.update(&[1u8]);
            c.str(env.event_id.as_str());
            c.str(env.phase.as_str());
            c.str(env.site_kind.as_str());
            c.str(env.decision.as_str());
            c.str(&env.how);
            c.h.update(&(env.grades.input.len() as u64).to_le_bytes());
            for g in &env.grades.input {
                c.str(&format!("{g:?}"));
            }
            c.opt(env.grades.output.map(|g| format!("{g:?}")).as_deref());
            c.opt(env.policy_ref.as_ref().map(ContentHash::as_str));
            c.str(&format!("{:?}", env.cert_mode));
            c.opt(env.basis_ref.as_deref());
            c.opt(env.parent_event.as_ref().map(EventId::as_str));
            c.opt(env.child_cause.as_ref().map(EventId::as_str));
        }
        c.finish()
    }

    // ── Dual projection (G11 / RFC-0013 I3) ────────────────────────────────────────────────────

    /// The **human projection** (G11 / RFC-0013 I3): a human-readable string. The content `id` is
    /// embedded so the human view carries the same identity as the machine one (I3). Shows severity,
    /// code, message, locus (when present), trace frames, and notes.
    ///
    /// Total: always returns a string for any well-formed `Diag`.
    ///
    /// # Guarantee: `Exact`
    /// Pure value transform; no approximation. (RFC-0016 §4.5, VR-5)
    #[must_use]
    pub fn human(&self) -> String {
        let id = self.content_hash();
        let mut out = String::new();
        out.push_str(&format!(
            "[{}] {}: {}",
            self.severity.as_str().to_uppercase(),
            self.code.as_str(),
            self.message
        ));
        if let Some(l) = &self.locus {
            let mut loc = String::new();
            if let Some(s) = &l.source {
                loc.push_str(s);
            }
            if let Some(line) = l.line {
                if !loc.is_empty() {
                    loc.push(':');
                }
                loc.push_str(&line.to_string());
                if let Some(col) = l.column {
                    loc.push(':');
                    loc.push_str(&col.to_string());
                }
            }
            if !loc.is_empty() {
                out.push_str(&format!("  (at {loc})"));
            }
        }
        if !self.trace.frames.is_empty() {
            out.push_str("\n  trace:");
            for f in &self.trace.frames {
                out.push_str(&format!("\n    {f}"));
            }
        }
        if !self.notes.is_empty() {
            out.push_str("\n  notes:");
            for n in &self.notes {
                out.push_str(&format!("\n    {n}"));
            }
        }
        out.push_str(&format!("\n  id: {}", id.as_str()));
        out
    }

    /// The **machine projection** (G11 / RFC-0013 I3): a lossless JSON record with the content `id`
    /// embedded. `from_json(machine(d))` recovers a record equal to `d` with an equal `content_hash`
    /// (the round-trip property, I3). The `id` field in JSON is informational: identity is recomputed
    /// from the recovered fields, so the round-trip is over semantic content, not over the wire string.
    ///
    /// Total: always returns a JSON string for any well-formed `Diag`.
    ///
    /// # Guarantee: `Exact`
    /// Pure value transform; no approximation. (RFC-0016 §4.5, VR-5)
    #[must_use]
    pub fn machine(&self) -> String {
        // Build a serde_json::Value so we can inject the `id` field alongside the record fields.
        let mut v = serde_json::to_value(self).expect("Diag always serializes to JSON");
        if let serde_json::Value::Object(map) = &mut v {
            map.insert(
                "id".to_owned(),
                serde_json::Value::String(self.content_hash().as_str().to_owned()),
            );
        }
        serde_json::to_string(&v).expect("a JSON Value always serializes")
    }

    /// Recover a `Diag` from its machine JSON projection (I3).
    ///
    /// The embedded `id` field is informational: because `Diag` does not carry
    /// `#[serde(deny_unknown_fields)]`, serde ignores unknown fields (including `id`) by default, so
    /// the machine projection round-trips transparently. Identity is recomputed from the recovered
    /// fields, so the round-trip is over semantic content, not the wire string.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] if `s` is not a well-formed `Diag` JSON record (C1: explicit
    /// error, never a partial/sentinel record).
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests;
