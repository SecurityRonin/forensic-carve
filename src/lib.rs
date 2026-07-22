//! `forensic-carve` — the SecurityRonin fleet carving contract and single-pass
//! sweep engine.
//!
//! This crate owns the medium-agnostic carving *contract* — the [`Carver`] trait,
//! [`Signature`], [`CarveContext`], [`CarvedItem`], and the [`RecoveryMethod`]
//! provenance vocabulary — plus (in later increments) the aho-corasick sweep engine
//! that runs one detection pass over disk-unallocated or memory regions and
//! dispatches capped windows to the matching carver.
//!
//! Fleet ADR 0001 (`ronin-issen/docs/decisions/`) is the governing design. A carver
//! sees only `&[u8]` windows and plain values, so the *same* carver serves disk and
//! memory sweeps; medium attribution (PID/VA/PFN, volume/run ids) is wrapped by the
//! driver *after* the call and never appears on [`CarvedItem`].
//!
//! Increment 1: the contract types only. The sweep engine lands in a later cycle.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// How (and how broadly) an artifact was recovered — the fleet-wide provenance
/// vocabulary (ADR 0001 §3). Carving *is* a recovery method, so this general
/// concept owns the plain name; the SQLite-record substrate detail lives in
/// `browser-forensic-carve` as `SqliteRecoveryMethod`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecoveryMethod {
    /// A deletion the filesystem itself recorded (an `$MFT` record with `IN_USE`
    /// cleared, an ext4 orphan inode). The `--deleted` flag.
    Tombstone,
    /// Tier-1 recovery from within a located artifact's own slack (freelist / WAL /
    /// `ElfChnk`). Default-on in the parser.
    FileInternalCarve,
    /// Tier-2 whole-image carving of unallocated space. The `--unallocated` flag.
    UnallocatedCarve,
    /// Recovered from a memory image (a process VA region or a physical frame).
    MemoryCarve,
}

impl RecoveryMethod {
    /// A stable serialization token, used when translating provenance onto the
    /// report model's `Evidence`/tags at orchestration (ADR 0001 §2). Never change a
    /// shipped token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RecoveryMethod::Tombstone => "tombstone",
            RecoveryMethod::FileInternalCarve => "file-internal-carve",
            RecoveryMethod::UnallocatedCarve => "unallocated-carve",
            RecoveryMethod::MemoryCarve => "memory-carve",
        }
    }
}

/// A magic signature a carver recognises: the bytes, plus the offset at which they
/// appear *within the artifact*, so a mid-artifact magic still anchors the window
/// start correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Signature {
    magic: &'static [u8],
    offset: usize,
}

impl Signature {
    /// A signature whose `magic` bytes appear `offset` bytes into the artifact.
    #[must_use]
    pub const fn new(magic: &'static [u8], offset: usize) -> Self {
        Self { magic, offset }
    }

    /// The magic bytes.
    #[must_use]
    pub const fn magic(&self) -> &'static [u8] {
        self.magic
    }

    /// The offset of the magic within the artifact (0 for a header magic).
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

/// What the engine does with carved items given their confidence. Defaults live in
/// each medium's driver, not hard-coded in the engine (ADR 0001 §8/C1).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfidencePolicy {
    /// Keep every item, even those with no or low confidence.
    KeepAll,
    /// Drop items whose confidence is below this floor.
    Minimum(f32),
}

/// The plain-values context handed to [`Carver::carve`]. Carries *only* values — the
/// window's absolute base offset in the source, and the confidence policy. It never
/// carries a `Read`/`Seek`, a VFS handle, or a memory provider: a carver that must
/// chase virtual pointers is a memory *walker*, not a medium-agnostic carver.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct CarveContext {
    base_offset: u64,
    policy: ConfidencePolicy,
}

impl CarveContext {
    /// A context for a window whose first byte sits at `base_offset` in the source.
    #[must_use]
    pub const fn at(base_offset: u64) -> Self {
        Self {
            base_offset,
            policy: ConfidencePolicy::KeepAll,
        }
    }

    /// Set the confidence policy (builder style).
    #[must_use]
    pub const fn with_policy(mut self, policy: ConfidencePolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The absolute offset of the window's first byte in the source.
    #[must_use]
    pub const fn base_offset(&self) -> u64 {
        self.base_offset
    }

    /// The confidence policy in effect.
    #[must_use]
    pub const fn policy(&self) -> ConfidencePolicy {
        self.policy
    }
}

/// A carved item's payload: either a bounded whole artifact (which re-enters the
/// normal classify→parse pipeline) or already-decoded records (for a loose chunk
/// with no containing file to re-parse — e.g. an orphaned `ElfChnk`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarvedPayload {
    /// Already-decoded records; the carver did the interpretation.
    Records,
    /// A bounded whole-artifact byte buffer for pipeline re-entry.
    ArtifactBytes(Vec<u8>),
}

/// One recovered item. **Medium-neutral**: it never carries PID/VA/PFN (memory) or
/// volume/run ids (disk) — that attribution is wrapped by the driver *after* the
/// carve call (ADR 0001 §8, `SweptItem`). Constructed via [`CarvedItem::records`] /
/// [`CarvedItem::artifact_bytes`], never a struct literal.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CarvedItem {
    format: &'static str,
    image_offset: u64,
    confidence: f32,
    method: RecoveryMethod,
    payload: CarvedPayload,
}

impl CarvedItem {
    /// A records-payload item (the carver decoded the records itself).
    #[must_use]
    pub fn records(
        format: &'static str,
        image_offset: u64,
        confidence: f32,
        method: RecoveryMethod,
    ) -> Self {
        Self {
            format,
            image_offset,
            confidence,
            method,
            payload: CarvedPayload::Records,
        }
    }

    /// An artifact-bytes item (a bounded whole artifact for pipeline re-entry).
    #[must_use]
    pub fn artifact_bytes(
        format: &'static str,
        image_offset: u64,
        confidence: f32,
        method: RecoveryMethod,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
            format,
            image_offset,
            confidence,
            method,
            payload: CarvedPayload::ArtifactBytes(bytes),
        }
    }

    /// The scheme-prefixed format id (e.g. `"sqlite"`, `"evtx-chunk"`).
    #[must_use]
    pub const fn format(&self) -> &'static str {
        self.format
    }

    /// The absolute offset of the item in the source.
    #[must_use]
    pub const fn image_offset(&self) -> u64 {
        self.image_offset
    }

    /// The carver's confidence in this item, normalized 0.0–1.0.
    #[must_use]
    pub const fn confidence(&self) -> f32 {
        self.confidence
    }

    /// How the item was recovered.
    #[must_use]
    pub const fn recovery_method(&self) -> RecoveryMethod {
        self.method
    }

    /// The item's payload.
    #[must_use]
    pub const fn payload(&self) -> &CarvedPayload {
        &self.payload
    }
}

/// A per-format carver. One impl per format, living in that format's PARSER crate,
/// seeing only `&[u8]` windows — medium-agnostic by construction, so the same carver
/// serves disk-unallocated and memory sweeps.
pub trait Carver {
    /// The scheme-prefixed format id this carver produces (e.g. `"sqlite"`).
    fn format(&self) -> &'static str;

    /// The magic signatures that anchor a candidate window for this format.
    fn signatures(&self) -> &[Signature];

    /// An upper bound on the bytes one hit may claim, so the engine can cap the
    /// window it materializes.
    fn max_window(&self) -> u64;

    /// Carve a (capped) window into zero or more items. Must validate structurally
    /// before emitting and grade confidence; a hit backed only by a short magic with
    /// no second independent check must not emit.
    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem>;
}
