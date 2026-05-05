#!/usr/bin/env python3
"""Find corresponding offsets between two versions of a PE binary.

Uses block matching (identical unchanged regions) to compute displacement
deltas, then searches the bounded region for anchor patterns.
"""

from typing import List, Optional, Tuple


def find_unchanged_regions(
    old: bytes, new: bytes, min_block: int = 16
) -> List[Tuple[int, int, int]]:
    """Find identical blocks between old and new binaries.

    Returns a sorted list of (old_off, new_off, size) tuples for blocks
    that are byte-identical in both binaries. Uses dict-based chunk
    indexing for O(n) performance.
    """
    # Index new binary by chunk
    new_chunks = {}
    for i in range(0, len(new) - min_block + 1, min_block):
        chunk = new[i : i + min_block]
        if chunk not in new_chunks:
            new_chunks[chunk] = i

    # Find matching chunks in old binary, sorted by offset
    raw_matches = []
    for i in range(0, len(old) - min_block + 1, min_block):
        chunk = old[i : i + min_block]
        if chunk in new_chunks:
            raw_matches.append((i, new_chunks[chunk]))

    if not raw_matches:
        return []

    # Extend each match as far as possible
    extended = []
    for old_off, new_off in raw_matches:
        size = 0
        while (old_off + size < len(old) and
               new_off + size < len(new) and
               old[old_off + size] == new[new_off + size]):
            size += 1
        if size >= min_block:
            extended.append((old_off, new_off, size))

    # Merge overlapping/adjacent regions
    merged = [extended[0]]
    for old_off, new_off, size in extended[1:]:
        prev = merged[-1]
        # Merge if overlapping or within min_block distance
        if old_off <= prev[0] + prev[2] + min_block:
            end_old = max(prev[0] + prev[2], old_off + size)
            end_new = max(prev[1] + prev[2], new_off + size)
            merged[-1] = (prev[0], prev[1], end_old - prev[0])
        else:
            merged.append((old_off, new_off, size))

    return merged


def find_corresponding_offset(
    old_data: bytes,
    new_data: bytes,
    old_off: int,
    pattern_len: int = 10,
    anchor: Optional[bytes] = None,
    search_radius: int = 512,
) -> Optional[int]:
    """Find the offset in new_data that corresponds to old_off in old_data.

    Uses unchanged blocks to compute a displacement delta, then searches
    the bounded region in new_data for the anchor pattern.

    Args:
        old_data: Full binary content of old version.
        new_data: Full binary content of new version.
        old_off: File offset in old binary.
        pattern_len: Expected length of the signature pattern.
        anchor: Optional bytes to search for (e.g., E8 instruction byte).
        search_radius: How far to search around the estimated offset.

    Returns:
        New file offset, or None if not found.
    """
    regions = find_unchanged_regions(old_data, new_data)
    if not regions:
        return None

    # Find nearest unchanged block before the offset
    delta = None
    for old_r, new_r, size in reversed(regions):
        if old_r + size <= old_off:
            delta = new_r - old_r
            break

    # Fallback: use nearest block after
    if delta is None:
        for old_r, new_r, size in regions:
            if old_r >= old_off + pattern_len:
                delta = new_r - old_r
                break

    if delta is None:
        return None

    estimated = old_off + delta

    if anchor:
        start = max(0, estimated - search_radius)
        end = min(len(new_data), estimated + search_radius)
        pos = new_data.find(anchor, start, end)
        if pos != -1:
            return pos
        return None

    return estimated


def extract_signature(data: bytes, offset: int, length: int = 10) -> str:
    """Extract a hex-space signature string from binary at offset."""
    return " ".join(f"{b:02x}" for b in data[offset : offset + length])


def extract_signature_with_wildcards(
    data: bytes, offset: int, length: int, wildcard_positions: set
) -> str:
    """Extract signature with specified positions wildcarded as '?'.

    Args:
        data: Binary data.
        offset: File offset to start reading.
        length: Number of bytes to extract.
        wildcard_positions: 0-based positions to replace with '?'.
    """
    parts = []
    for i in range(length):
        if i in wildcard_positions:
            parts.append("?")
        else:
            parts.append(f"{data[offset + i]:02x}")
    return " ".join(parts)
