"""Find corresponding offsets between two PE binary versions.

Pure Python, stdlib only. Uses chunk-based block matching to find
regions of identical bytes between binary versions, then uses those
as anchors to find corresponding offsets.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class BlockMatchResult:
    old_offset: int
    new_offset: int
    confidence: float  # 0.0 to 1.0
    window_before: int
    window_after: int


def find_unchanged_regions(
    old_data: bytes,
    new_data: bytes,
    min_block_size: int = 16,
    max_regions: int = 500,
) -> list[tuple[int, int, int]]:
    """Find regions of identical bytes between two binaries.

    Returns sorted list of (old_offset, new_offset, size) tuples.
    Uses dict-based chunk indexing for O(n) performance.
    """
    # Build chunk index for old binary
    chunk_map: dict[bytes, list[int]] = {}
    for i in range(len(old_data) - min_block_size + 1):
        chunk = old_data[i : i + min_block_size]
        if chunk not in chunk_map:
            chunk_map[chunk] = []
        chunk_map[chunk].append(i)

    # Find matching chunks in new binary
    raw_matches: list[tuple[int, int]] = []
    seen_new: set[int] = set()
    for new_off in range(len(new_data) - min_block_size + 1):
        chunk = new_data[new_off : new_off + min_block_size]
        if chunk in chunk_map and new_off not in seen_new:
            for old_off in chunk_map[chunk]:
                raw_matches.append((old_off, new_off))
            seen_new.add(new_off)

    if not raw_matches:
        return []

    # Sort by old offset
    raw_matches.sort()

    # Extend matches: for each matching chunk, extend forward while bytes match
    extended: list[tuple[int, int, int]] = []
    for old_off, new_off in raw_matches:
        size = 0
        while (
            old_off + size < len(old_data)
            and new_off + size < len(new_data)
            and old_data[old_off + size] == new_data[new_off + size]
        ):
            size += 1
        if size >= min_block_size:
            extended.append((old_off, new_off, size))

    # Merge overlapping/nearby regions
    merged: list[tuple[int, int, int]] = []
    for old_off, new_off, size in extended:
        if merged and old_off <= merged[-1][0] + merged[-1][2] + 8:
            prev_old, prev_new, prev_size = merged[-1]
            new_size = max(
                size + (old_off - prev_old),
                prev_size + (new_off - prev_new),
            )
            merged[-1] = (prev_old, prev_new, prev_size + new_size)
        else:
            merged.append((old_off, new_off, size))

    # Sort by old offset
    merged.sort()
    return merged[:max_regions]


def _compute_context_similarity(
    old_data: bytes,
    new_data: bytes,
    old_off: int,
    new_off: int,
    window: int = 256,
) -> float:
    """Compute byte similarity ratio between windows around two offsets."""
    old_start = max(0, old_off - window)
    old_end = min(len(old_data), old_off + window)
    offset = old_start - (new_off - window)
    new_start = max(0, offset)
    new_end = min(len(new_data), offset + (old_end - old_start))

    old_win = old_data[old_start:old_end]
    new_win = new_data[new_start:new_end]

    if not old_win or not new_win:
        return 0.0

    # Align windows
    min_len = min(len(old_win), len(new_win))
    if min_len == 0:
        return 0.0

    matches = sum(
        1
        for i in range(min_len)
        if old_win[i] == new_win[i]
    )
    return matches / min_len


def find_corresponding_offset(
    old_data: bytes,
    new_data: bytes,
    old_offset: int,
    pattern_len: int,
    anchor_byte: Optional[bytes] = None,
    anchor_pos: int = 0,
) -> Optional[BlockMatchResult]:
    """Find the offset in new_data that corresponds to old_offset in old_data.

    Algorithm:
    1. Find unchanged regions between binaries
    2. Bracket: nearest unchanged block before and after old_offset
    3. Compute offset delta from brackets
    4. Search bounded region for anchor pattern
    5. Return highest confidence match
    """
    regions = find_unchanged_regions(old_data, new_data)
    if not regions:
        return None

    # Find brackets
    block_before = None
    block_after = None
    for old_off, new_off, size in regions:
        if old_off + size <= old_offset:
            block_before = (old_off, new_off, size)
        if old_off >= old_offset + pattern_len and block_after is None:
            block_after = (old_off, new_off, size)
            break

    # Compute estimated new offset
    if block_before and block_after:
        old_before_end = block_before[0] + block_before[2]
        old_after_start = block_after[0]
        new_before_end = block_before[1] + block_before[2]
        new_after_start = block_after[1]

        # Linear interpolation
        old_range = old_after_start - old_before_end
        new_range = new_after_start - new_before_end
        old_rel = old_offset - old_before_end

        if old_range > 0:
            ratio = old_rel / old_range
            est_new = new_before_end + int(ratio * new_range)
        else:
            est_new = new_before_end

        search_start = max(0, est_new - 256)
        search_end = min(len(new_data), est_new + 256 + new_range)
    elif block_before:
        # Extrapolate from before block
        delta = block_before[1] - block_before[0]
        est_new = old_offset + delta
        search_start = max(0, est_new - 512)
        search_end = min(len(new_data), est_new + 512)
    elif block_after:
        delta = block_after[1] - block_after[0]
        est_new = old_offset + delta
        search_start = max(0, est_new - 512)
        search_end = min(len(new_data), est_new + 512)
    else:
        # No brackets found — search near estimated position from first block
        delta = regions[0][1] - regions[0][0]
        est_new = old_offset + delta
        search_start = max(0, est_new - 1024)
        search_end = min(len(new_data), est_new + 1024)

    # Search for anchor in bounded region
    old_pattern = old_data[old_offset : old_offset + pattern_len]
    candidates: list[tuple[int, float]] = []

    if anchor_byte:
        # Search for the anchor byte at the specified position within the pattern
        anchor_in_pattern = old_pattern[anchor_pos : anchor_pos + len(anchor_byte)]
        search_region = new_data[search_start:search_end]

        pos = 0
        while True:
            pos = search_region.find(anchor_in_pattern, pos)
            if pos == -1:
                break
            candidate_off = search_start + pos - anchor_pos
            if candidate_off < 0 or candidate_off + pattern_len > len(new_data):
                pos += 1
                continue

            # Check that the non-constant bytes match
            new_at_candidate = new_data[
                candidate_off : candidate_off + pattern_len
            ]
            # Compare bytes at non-anchor positions
            match_count = 0
            total_checked = 0
            for i in range(pattern_len):
                if i != anchor_pos:
                    if old_pattern[i] == new_at_candidate[i]:
                        match_count += 1
                    total_checked += 1

            if total_checked > 0:
                byte_sim = match_count / total_checked
                ctx_sim = _compute_context_similarity(
                    old_data, new_data, old_offset, candidate_off
                )
                confidence = (byte_sim * 0.5) + (ctx_sim * 0.5)
                candidates.append((candidate_off, confidence))

            pos += 1
    else:
        # No anchor — try exact pattern match first
        search_region = new_data[search_start:search_end]
        pos = search_region.find(old_pattern)
        if pos != -1:
            candidate_off = search_start + pos
            ctx_sim = _compute_context_similarity(
                old_data, new_data, old_offset, candidate_off
            )
            candidates.append((candidate_off, 0.5 + ctx_sim * 0.5))

    if not candidates:
        return None

    # Return best candidate
    candidates.sort(key=lambda x: x[1], reverse=True)
    best_off, best_conf = candidates[0]

    if best_conf < 0.3:
        return None

    # Compute window info
    window_before = 0
    window_after = 0
    for old_off, new_off, size in regions:
        if old_off + size <= old_offset and new_off + size <= best_off:
            window_before = max(
                window_before, best_off - (new_off + size)
            )
        if old_off >= old_offset + pattern_len and new_off >= best_off + pattern_len:
            window_after = max(
                window_after, new_off - (best_off + pattern_len)
            )

    return BlockMatchResult(
        old_offset=old_offset,
        new_offset=best_off,
        confidence=round(best_conf, 3),
        window_before=window_before,
        window_after=window_after,
    )


def extract_signature(
    data: bytes,
    offset: int,
    length: int,
    wildcard_positions: Optional[list[int]] = None,
) -> str:
    """Extract bytes and produce a Sig-compatible hex-space pattern string.

    Byte positions in wildcard_positions become '?' wildcards.
    """
    chunk = data[offset : offset + length]
    if wildcard_positions is None:
        wildcard_positions = []

    parts = []
    for i, b in enumerate(chunk):
        if i in wildcard_positions:
            parts.append("?")
        else:
            parts.append(f"{b:02X}")
    return " ".join(parts)
