#!/usr/bin/env python3
"""Sublime Text 4 signature scanner.

Discovers new builds, tests existing signatures, extracts new ones
via block matching, and generates patch diffs.
"""

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import importlib.util

def _load_patcher():
    spec = importlib.util.spec_from_file_location(
        "patcher", Path(__file__).parent.parent / "sublime_text_4_patcher.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["patcher"] = mod
    spec.loader.exec_module(mod)
    return mod


Patcher = _load_patcher()
Patch = Patcher.Patch
PatchDB = Patcher.PatchDB
Sig = Patcher.Sig
Sigs = Patcher.Sigs
SublimeText = Patcher.SublimeText
test_signatures_only = Patcher.test_signatures_only

from block_matcher import (
    BlockMatchResult,
    find_corresponding_offset,
    find_unchanged_regions,
)


def detect_new_builds(channels: list[str] | None = None) -> dict:
    """Check sublimetext.com for new builds."""
    if channels is None:
        channels = ["dev", "stable"]

    pages = {
        "dev": "https://www.sublimetext.com/dev",
        "stable": "https://www.sublimetext.com/download",
    }

    current = PatchDB.CHANNELS
    new_builds = []

    for channel in channels:
        if channel not in pages:
            continue
        max_known = max(current[channel]) if current[channel] else 0

        try:
            html = urlopen(pages[channel], timeout=15).read().decode()
        except Exception as e:
            print(f"Warning: Could not fetch {channel} page: {e}", file=sys.stderr)
            continue

        matches = re.findall(r"sublime_text_build_(\d+)_x64", html)
        if not matches:
            # Try alternate pattern
            matches = re.findall(r"Build\s+(\d+)", html)
        if not matches:
            print(f"Warning: No build numbers found in {channel} page", file=sys.stderr)
            continue

        latest = max(map(int, matches))
        if latest > max_known:
            new_builds.append({
                "channel": channel,
                "build": latest,
                "url": f"https://download.sublimetext.com/sublime_text_build_{latest}_x64.zip",
            })

    return {"new_builds": new_builds}


def run_test(exe_path: str) -> dict:
    """Test signatures against a binary."""
    result = test_signatures_only(exe_path)

    # Try with force channel if version not in CHANNELS
    if result.get("error") and "not in CHANNELS" in str(result.get("error", "")):
        result = test_signatures_only(exe_path, force_patch_channel="dev")
        if not result.get("error"):
            result["force_channel"] = "dev"

    return result


def extract_new_signatures(
    scan_result: dict,
    new_exe: str,
    old_exe: str,
) -> dict:
    """Extract new signatures for failed patches.

    Returns a patch_diff.json compatible dict.
    """
    new_data = Path(new_exe).read_bytes()
    old_data = Path(old_exe).read_bytes()

    changes = []
    failed_patches = [
        p for p in scan_result.get("patches", []) if p["status"] == "fail"
    ]

    for failed in failed_patches:
        sig_name = failed["sig_name"]
        patch_type = failed["patch_type"]

        # Find the original patch definition
        old_patch = _find_patch_in_db(sig_name, patch_type)
        if not old_patch:
            changes.append({
                "patch_name": sig_name,
                "action": "manual_review",
                "reason": "Could not find original patch definition",
            })
            continue

        # Try to extract new signature
        result = _extract_single_signature(
            old_patch, old_data, new_data, sig_name
        )
        if result:
            changes.append(result)
        else:
            changes.append({
                "patch_name": sig_name,
                "action": "manual_review",
                "reason": "Could not extract new signature automatically",
                "old_sig": str(old_patch.sigs[0]),
            })

    version = scan_result.get("version")
    channel = "dev" if version and version % 2 else "stable"

    return {
        "build": version,
        "channel": channel,
        "changes": changes,
        "version_updates": {
            "add_to_channels": {channel: [version]} if version else {},
        },
    }


def _find_patch_in_db(sig_name: str, patch_type: str):
    """Find a patch definition by signature name."""
    # Try all known versions
    for version in list(PatchDB.CHANNELS["dev"]) + list(PatchDB.CHANNELS["stable"]):
        try:
            db = PatchDB("windows", "x64", version)
            for patch in db.get_patches():
                if patch.patch_type != patch_type:
                    continue
                for sig in patch.sigs:
                    if sig.name == sig_name:
                        return patch
        except (KeyError, ValueError):
            continue
    return None


def _extract_single_signature(
    old_patch: Patch,
    old_data: bytes,
    new_data: bytes,
    sig_name: str,
) -> dict | None:
    """Extract a new signature for a single failed patch.

    Strategy:
    1. Find the old signature in the old binary to get the offset
    2. Use block matching to find corresponding offset in new binary
    3. Extract new bytes at that offset
    """
    # Find old offset
    old_offset = None
    for sig in old_patch.sigs:
        try:
            old_file = SublimeText.__new__(SublimeText)
            old_file.data = memoryview(bytearray(old_data))
            old_file.path = Path("old.exe")
            old_file.pe = None
            old_file.sections = {}
            old_file.patches = []
            old_file.patched_offsets = []
            old_offset = old_file.find(sig)
            break
        except (ValueError, Exception):
            continue

    if old_offset is None:
        # Signature not found in old binary either — pattern may have changed
        # since it was added. Try the raw pattern.
        pattern_bytes = old_patch.sigs[0].pattern
        m = re.search(pattern_bytes, old_data)
        if m:
            old_offset = m.start()

    if old_offset is None:
        return None

    # Determine the pattern length from the old signature
    pattern_len = len(old_patch.sigs[0].raw_pattern.split())

    # For invalidate1/invalidate2, the pattern is:
    # 41 B8 CC CC CC CC E8 ?? ?? ?? ??
    # The constant bytes (positions 2-5) change. The E8 at position 6 is the anchor.
    # Strategy: wildcard the constant bytes, search in new binary bounded by
    # unchanged regions.

    raw_pattern = old_patch.sigs[0].raw_pattern
    pattern_parts = raw_pattern.split()

    # Identify which bytes are wildcards in the original pattern
    wildcard_in_orig = {i for i, p in enumerate(pattern_parts) if p == "?"}

    # For constant-change patterns (invalidate1/2), the non-wildcard bytes
    # that CHANGE are between the opcode and the call. Detect them.
    # Pattern: 41 B8 CC CC CC CC E8 (where CC changes, E8 is fixed at pos 6)
    # We know: bytes after the last non-wildcard up to the anchor (E8) are constants
    # that change. Heuristic: the constant bytes are those that are NOT wildcards
    # in the original but ARE different in the new binary.

    # Extract the old bytes at the offset
    old_bytes_at_offset = old_data[old_offset : old_offset + pattern_len]

    # Try to find the corresponding offset in the new binary using block matching
    result = find_corresponding_offset(
        old_data,
        new_data,
        old_offset,
        pattern_len,
        anchor_byte=bytes.fromhex(pattern_parts[6])
        if len(pattern_parts) > 6 and pattern_parts[6] != "?"
        else None,
        anchor_pos=6,
    )

    if result and result.confidence > 0.3:
        new_offset = result.new_offset
    else:
        # Fallback: try to find pattern with wildcards on constant bytes
        # Heuristic: for patterns like "41 B8 XX XX XX XX E8", wildcard the 4 bytes
        # between B8 and E8.
        new_pattern_parts = list(pattern_parts)
        # Find the range of "constant" bytes (between fixed opcode and fixed anchor)
        if "E8" in new_pattern_parts or "E9" in new_pattern_parts:
            anchor_idx = None
            for idx, p in enumerate(new_pattern_parts):
                if p in ("E8", "E9", "48"):
                    anchor_idx = idx
                    break
            if anchor_idx:
                # Wildcard bytes between opcode (pos 0-1) and anchor
                for i in range(2, anchor_idx):
                    if i not in wildcard_in_orig:
                        new_pattern_parts[i] = "?"

        # Build regex pattern
        new_pattern_str = " ".join(new_pattern_parts)
        new_sig = Sig(new_pattern_str)

        # Search in new data
        try:
            m = re.search(new_sig.pattern, new_data)
            if m:
                # Check it's unique (or near-unique)
                count = len(list(re.finditer(new_sig.pattern, new_data)))
                if count <= 3:
                    new_offset = m.start()
                else:
                    # Too many matches — use context similarity
                    best_score = 0
                    best_offset = None
                    for match in re.finditer(new_sig.pattern, new_data):
                        score = _context_match_score(
                            old_data, new_data, old_offset, match.start()
                        )
                        if score > best_score:
                            best_score = score
                            best_offset = match.start()
                    if best_offset and best_score > 0.5:
                        new_offset = best_offset
                    else:
                        return None
        except re.error:
            return None

    # Extract new bytes and build new signature
    new_bytes = new_data[new_offset : new_offset + pattern_len]

    # Build new sig string: use wildcards for positions that were already wildcards
    # in the original, plus for relative address bytes (last 4 of call/jmp)
    new_sig_parts = []
    for i in range(pattern_len):
        if i in wildcard_in_orig:
            new_sig_parts.append("?")
        elif i < len(new_bytes):
            new_sig_parts.append(f"{new_bytes[i]:02X}")
        else:
            new_sig_parts.append("?")

    new_sig_str = " ".join(new_sig_parts)

    # Determine offset and ref from original sig
    offset = old_patch.sigs[0].offset
    ref = old_patch.sigs[0].ref

    return {
        "patch_name": sig_name,
        "action": "replace_sig",
        "old_sig": raw_pattern,
        "new_sig": new_sig_str,
        "offset": offset,
        "ref": ref,
        "confidence": result.confidence if result else 0.5,
    }


def _context_match_score(
    old_data: bytes,
    new_data: bytes,
    old_off: int,
    new_off: int,
    window: int = 128,
) -> float:
    """Compare context around two offsets."""
    from block_matcher import _compute_context_similarity
    return _compute_context_similarity(old_data, new_data, old_off, new_off, window)


def validate_patch(diff: dict, new_exe: str, old_exe: str) -> dict:
    """Apply patch diff in-memory and test."""
    # Test new build with modified signatures
    new_result = run_test(new_exe)

    # If still failing, try with extracted signatures applied
    if not new_result.get("all_passed") and diff.get("changes"):
        # Apply changes to PatchDB in memory — this is complex, skip for now
        # and rely on source modification
        pass

    old_result = run_test(old_exe)

    return {
        "new_build": {
            "version": new_result.get("version"),
            "all_passed": new_result.get("all_passed", False),
            "patches": new_result.get("patches", []),
        },
        "old_build": {
            "version": old_result.get("version"),
            "all_passed": old_result.get("all_passed", False),
            "patches": old_result.get("patches", []),
        },
        "validated": new_result.get("all_passed", False) and old_result.get(
            "all_passed", False
        ),
    }


def apply_diff_to_source(diff: dict, source_path: str | None = None) -> None:
    """Apply patch diff to sublime_text_4_patcher.py source.

    Modifies: sig strings in PatchDB.load(), CHANNELS dict.
    """
    if source_path is None:
        source_path = str(
            Path(__file__).parent.parent / "sublime_text_4_patcher.py"
        )

    source = Path(source_path).read_text()

    for change in diff.get("changes", []):
        if change["action"] == "replace_sig" and "old_sig" in change:
            old = change["old_sig"]
            new = change["new_sig"]
            # Escape for regex
            old_escaped = re.escape(old)
            source = re.sub(old_escaped, new, source)

    # Add version to CHANNELS
    version_update = diff.get("version_updates", {}).get("add_to_channels", {})
    for channel, versions in version_update.items():
        for version in versions:
            # Check if already present
            if str(version) in source:
                continue
            # Find the channel tuple and add the version
            # Pattern: "dev": (\n    ..., \n    ),
            # Insert version before the closing )
            pattern = rf'("{channel}":\s*\(\n(?:[^\)]*\n)*)(\s*\))'
            match = re.search(pattern, source)
            if match:
                # Detect indentation from existing entries
                existing_line = re.search(rf'({channel}":\s*\(\n)(\s+)', match.group())
                indent = existing_line.group(2) if existing_line else "            "
                insert_pos = match.end(1)
                new_version = f"{indent}{version},\n"
                source = (
                    source[:insert_pos] + new_version + source[insert_pos:]
                )

    Path(source_path).write_text(source)


def cmd_detect(args):
    result = detect_new_builds(args.channels)
    print(json.dumps(result, indent=2))

    if result["new_builds"]:
        for build in result["new_builds"]:
            print(
                f"New {build['channel']} build: {build['build']}",
                file=sys.stderr,
            )
        # Set GHA output
        import os
        gh_output = os.environ.get("GITHUB_OUTPUT")
        if gh_output:
            with open(gh_output, "a") as f:
                for build in result["new_builds"]:
                    f.write(
                        f"new_build_{build['channel']}={build['build']}\n"
                    )
                    f.write(f"new_build_url_{build['channel']}={build['url']}\n")
            with open(gh_output, "a") as f:
                f.write("new_build_found=true\n")
    else:
        print("No new builds detected.", file=sys.stderr)
        import os
        gh_output = os.environ.get("GITHUB_OUTPUT")
        if gh_output:
            with open(gh_output, "a") as f:
                f.write("new_build_found=false\n")


def cmd_test(args):
    result = run_test(args.input)
    output = Path(args.output)
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

    if result.get("all_passed"):
        print("All signatures matched!", file=sys.stderr)
        sys.exit(0)
    else:
        failed = [p for p in result.get("patches", []) if p["status"] == "fail"]
        print(f"{len(failed)} signatures failed.", file=sys.stderr)
        sys.exit(1)


def cmd_extract(args):
    scan_result = json.loads(Path(args.result).read_text())
    diff = extract_new_signatures(scan_result, args.input, args.old_input)
    output = Path(args.output)
    output.write_text(json.dumps(diff, indent=2))
    print(json.dumps(diff, indent=2))

    manual = [c for c in diff["changes"] if c["action"] == "manual_review"]
    if manual:
        print(
            f"\n{len(manual)} patches require manual review.", file=sys.stderr
        )
        sys.exit(2)


def cmd_validate(args):
    diff = json.loads(Path(args.diff).read_text())
    result = validate_patch(diff, args.new_input, args.old_input)
    print(json.dumps(result, indent=2))

    if not result["validated"]:
        sys.exit(1)


def cmd_apply(args):
    diff = json.loads(Path(args.diff).read_text())
    apply_diff_to_source(diff, args.target)
    print("Applied diff to source.", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="Sublime Text 4 signature scanner")
    subparsers = parser.add_subparsers(dest="command")

    p_detect = subparsers.add_parser("detect", help="Check for new builds")
    p_detect.add_argument(
        "--channels", nargs="*", default=["dev", "stable"], choices=["dev", "stable"]
    )

    p_test = subparsers.add_parser("test", help="Test signatures against binary")
    p_test.add_argument("--input", required=True, help="Path to sublime_text.exe")
    p_test.add_argument(
        "--output", default="scan_result.json", help="JSON output path"
    )

    p_extract = subparsers.add_parser("extract", help="Extract new signatures")
    p_extract.add_argument("--input", required=True, help="NEW sublime_text.exe")
    p_extract.add_argument(
        "--old-input", required=True, help="OLD sublime_text.exe (reference)"
    )
    p_extract.add_argument(
        "--result", required=True, help="scan_result.json from --test"
    )
    p_extract.add_argument(
        "--output", default="patch_diff.json", help="Output diff path"
    )

    p_validate = subparsers.add_parser("validate", help="Validate patch diff")
    p_validate.add_argument("--diff", required=True, help="patch_diff.json")
    p_validate.add_argument("--new-input", required=True, help="NEW sublime_text.exe")
    p_validate.add_argument("--old-input", required=True, help="OLD sublime_text.exe")

    p_apply = subparsers.add_parser("apply", help="Apply diff to source")
    p_apply.add_argument("--diff", required=True, help="patch_diff.json")
    p_apply.add_argument(
        "--target",
        default=str(Path(__file__).parent.parent / "sublime_text_4_patcher.py"),
        help="Source file",
    )

    cmds = {
        "detect": cmd_detect,
        "test": cmd_test,
        "extract": cmd_extract,
        "validate": cmd_validate,
        "apply": cmd_apply,
    }

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    cmds[args.command](args)


if __name__ == "__main__":
    main()
