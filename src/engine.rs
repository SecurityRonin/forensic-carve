//! The single-pass sweep engine (fleet ADR 0001 §2/§4/§8).
//!
//! One aho-corasick detection pass over the supplied regions; each magic hit is
//! converted to an absolute source offset, the carver-declared window is
//! materialized (detection ≠ materialization — a large artifact is not truncated to
//! a scan chunk), the owning carver runs, and the medium-neutral [`CarvedItem`] is
//! wrapped in a [`SweptItem`] carrying the region's attribution tag. The engine owns
//! both the chunk-boundary overlap and the window materialization; medium defaults
//! (chunk size, confidence policy) live with the caller in [`CarveOptions`].

use aho_corasick::AhoCorasick;

use crate::{CarveContext, CarvedItem, Carver, ConfidencePolicy, RecoveryMethod};

/// A positioned-read edge over the source being swept. Disk drivers implement it
/// over `forensic-vfs` positioned reads; memory drivers over `read_virt`. A short
/// read (fewer bytes than requested) signals a gap or end-of-source — the engine
/// treats the window as truncated, never fabricating bytes.
pub trait RegionSource {
    /// Read into `buf` starting at absolute `offset`; return the number of bytes
    /// actually read (0 at/after the end, short at a gap).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> usize;
}

/// A contiguous span of the source to sweep, plus an opaque medium-specific
/// attribution `tag` (disk: volume/run id; memory: PID/VA) that rides back out on
/// each [`SweptItem`] — keeping [`CarvedItem`] itself medium-neutral (ADR §8/C1).
#[derive(Debug, Clone)]
pub struct Region<R> {
    /// Absolute start offset of the span in the source.
    pub start: u64,
    /// Length of the span in bytes.
    pub len: u64,
    /// Medium-specific attribution carried back on each item.
    pub tag: R,
}

/// A carved item plus where it came from: the source-relative offset and the
/// region's attribution tag. Keeps `CarvedItem` medium-neutral (ADR §8/C1).
#[derive(Debug, Clone)]
pub struct SweptItem<R> {
    /// The region attribution tag the item was found under.
    pub region: R,
    /// The item's absolute offset in the source.
    pub offset: u64,
    /// The medium-neutral carved item.
    pub item: CarvedItem,
}

/// Engine knobs. Public fields, medium defaults set by the caller's driver.
#[derive(Debug, Clone)]
pub struct CarveOptions {
    /// Bytes read per detection chunk (overlap is added automatically).
    pub chunk_size: usize,
    /// Hard cap on the window materialized per hit (an alloc-bomb backstop; the
    /// carver's own `max_window` caps it further).
    pub max_window: u64,
    /// What to do with carved items by confidence.
    pub confidence_policy: ConfidencePolicy,
    /// The recovery method this sweep carves under — the driver's medium/tier
    /// (disk unallocated → `UnallocatedCarve`, memory → `MemoryCarve`). Threaded into
    /// each carver's `CarveContext`.
    pub recovery_method: RecoveryMethod,
}

impl Default for CarveOptions {
    fn default() -> Self {
        Self {
            chunk_size: 1 << 20,   // 1 MiB
            max_window: 256 << 20, // 256 MiB
            confidence_policy: ConfidencePolicy::KeepAll,
            recovery_method: RecoveryMethod::UnallocatedCarve,
        }
    }
}

/// Run one detection pass over `regions`, dispatching capped windows to the matching
/// carver. Returns the carved items, each wrapped with its source offset and region
/// tag. Panic-free: a build failure or empty pattern set yields no items rather than
/// erroring.
pub fn sweep<S, R>(
    source: &S,
    regions: impl IntoIterator<Item = Region<R>>,
    carvers: &[&dyn Carver],
    opts: &CarveOptions,
) -> Vec<SweptItem<R>>
where
    S: RegionSource,
    R: Clone,
{
    // Build the pattern set: each signature maps back to (carver index, signature).
    let mut patterns: Vec<&[u8]> = Vec::new();
    let mut meta: Vec<(usize, crate::Signature)> = Vec::new();
    for (ci, c) in carvers.iter().enumerate() {
        for sig in c.signatures() {
            patterns.push(sig.magic());
            meta.push((ci, *sig));
        }
    }
    if patterns.is_empty() {
        return Vec::new();
    }
    let Ok(ac) = AhoCorasick::new(&patterns) else {
        return Vec::new(); // cov:unreachable: patterns is non-empty (guarded above) and within aho-corasick's build limits
    };

    // Overlap carried across chunk boundaries so a magic spanning the boundary is
    // still found in exactly one chunk's scan buffer.
    let longest = patterns.iter().map(|p| p.len()).max().unwrap_or(0);
    let overlap = longest.saturating_sub(1);
    // A chunk must be at least the longest magic, or a magic can't fit in the scan
    // buffer (carry + chunk) and would be missed. The default 1 MiB dwarfs any magic;
    // this only clamps up a pathologically small configured chunk_size.
    let chunk_size = opts.chunk_size.max(longest).max(1);

    let mut out: Vec<SweptItem<R>> = Vec::new();

    for region in regions {
        let region_end = region.start.saturating_add(region.len);
        let mut carry: Vec<u8> = Vec::new();
        let mut pos = region.start;

        while pos < region_end {
            let want = chunk_size.min(usize_saturating(region_end - pos));
            if want == 0 {
                break; // cov:unreachable: loop guard `pos < region_end` ⇒ region_end - pos >= 1, and chunk_size >= 1
            }
            let mut chunk = vec![0u8; want];
            let n = source.read_at(pos, &mut chunk);
            if n == 0 {
                break;
            }
            chunk.truncate(n);

            // Scan buffer = carry (overlap tail of the previous chunk) + fresh chunk.
            let chunk_new_start = pos;
            let buffer_base = chunk_new_start - carry.len() as u64;
            let mut buffer = Vec::with_capacity(carry.len() + chunk.len());
            buffer.extend_from_slice(&carry);
            buffer.extend_from_slice(&chunk);

            for m in ac.find_overlapping_iter(&buffer) {
                let abs_start = buffer_base + m.start() as u64;
                let abs_end = buffer_base + m.end() as u64;
                // Dedup: a match fully inside the carry was already reported by the
                // previous chunk. A straddling match (ends at/after the fresh bytes)
                // is reported here, once.
                if abs_end <= chunk_new_start {
                    continue;
                }
                let (cidx, sig) = &meta[m.pattern().as_usize()];
                // Anchor the artifact start (magic may sit mid-artifact).
                let Some(artifact_start) = abs_start.checked_sub(sig.offset() as u64) else {
                    continue;
                };
                let Some(carver) = carvers.get(*cidx) else {
                    continue; // cov:unreachable: meta indices come from `carvers`
                };

                // Materialize ONLY the carver-declared window (detection != materialization).
                let window_len = usize_saturating(carver.max_window().min(opts.max_window));
                if window_len == 0 {
                    continue;
                }
                let mut window = vec![0u8; window_len];
                let got = source.read_at(artifact_start, &mut window);
                window.truncate(got);

                let ctx = CarveContext::at(artifact_start)
                    .with_method(opts.recovery_method)
                    .with_policy(opts.confidence_policy);
                for item in carver.carve(&window, &ctx) {
                    if keeps(opts.confidence_policy, item.confidence()) {
                        out.push(SweptItem {
                            region: region.tag.clone(),
                            offset: item.image_offset(),
                            item,
                        });
                    }
                }
            }

            // Carry the overlap tail of the fresh chunk into the next iteration.
            let ov = overlap.min(chunk.len());
            carry = chunk[chunk.len() - ov..].to_vec();
            pos += n as u64;
        }
    }

    out
}

fn keeps(policy: ConfidencePolicy, confidence: f32) -> bool {
    match policy {
        ConfidencePolicy::KeepAll => true,
        ConfidencePolicy::Minimum(floor) => confidence >= floor,
    }
}

/// Saturating `u64 -> usize` (on 32-bit hosts a huge span clamps to `usize::MAX`).
fn usize_saturating(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}
