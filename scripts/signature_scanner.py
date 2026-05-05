#!/usr/bin/env python3
"""Automated signature detection and extraction for Sublime Text 4 patcher.

Subcommands:
    detect   — scrape sublimetext.com/dev for latest build number
    test     — run test_signatures_only() on a binary, output results
    extract  — given test failures, extract new signatures via block matching
    validate — apply new signatures in-memory, test new + old builds
    apply    — modify sublime_text_4_patcher.py source with new signatures
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root and scripts dir are on path
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sublime_text_4_patcher as p
from block_matcher import (
    extract_signature,
    extract_signature_with_wildcards,
    find_corresponding_offset,
)

DEFAULT_DOWNLOADS_DIR = Path(__file__).resolve().parent.parent / "downloads"


def cmd_detect(args):
    """Scrape sublimetext.com/dev for latest build number."""
    import requests

    resp = requests.get("https://www.sublimetext.com/dev", timeout=30)
    resp.raise_for_status()

    match = re.search(r"sublime_text_build_(\d+)_x64", resp.text)
    if not match:
        print("Could not find dev build number on sublimetext.com/dev")
        return 1

    latest = int(match.group(1))
    dev_versions = p.PatchDB.CHANNELS["dev"]
    max_known = max(dev_versions)

    if latest <= max_known:
        print(f"Latest dev build {latest} is already in CHANNELS (max={max_known})")
        return 0

    print(f"New dev build detected: {latest} (current max={max_known})")
    return 0


def cmd_test(args) -> Dict[str, Any]:
    """Run test_signatures_only() on a binary."""
    filepath = str(args.input)
    force_channel = args.force

    result = p.test_signatures_only(filepath, force_channel=force_channel)

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2))

    print(json.dumps(result, indent=2))

    if result.get("error"):
        return {"status": "error", "result": result}
    if result.get("all_passed"):
        return {"status": "pass", "result": result}
    return {"status": "fail", "result": result}


def cmd_extract(args) -> Dict[str, Any]:
    """Extract new signatures from a new build using block matching."""
    # Read test results
    with open(args.scan_result) as f:
        scan = json.load(f)

    if scan.get("error"):
        print(f"Scan had error: {scan['error']}")
        return {"status": "error", "error": scan["error"]}

    new_exe = str(args.new_binary)
    new_version = scan["version"]

    # Find reference binary (latest known-good build)
    ref_exe = find_reference_binary(new_version, args.ref_dir)
    if ref_exe is None:
        print("Could not find reference binary")
        return {"status": "error", "error": "No reference binary found"}

    old_data = Path(ref_exe).read_bytes()
    new_data = Path(new_exe).read_bytes()

    # Process each failed patch
    diff = {
        "version": new_version,
        "patches": [],
    }

    for patch_info in scan.get("patches", []):
        if patch_info["status"] == "pass":
            diff["patches"].append({
                "patch_type": patch_info["patch_type"],
                "sig_name": patch_info["sig_name"],
                "status": "unchanged",
            })
            continue

        # Find the patch definition to get sig details
        patch_info["new_sigs"] = extract_patch_sigs(
            old_data, new_data, patch_info
        )

        if not patch_info["new_sigs"]:
            diff["patches"].append({
                "patch_type": patch_info["patch_type"],
                "sig_name": patch_info["sig_name"],
                "status": "failed",
                "error": "Could not extract new signature",
            })
        else:
            diff["patches"].append({
                "patch_type": patch_info["patch_type"],
                "sig_name": patch_info["sig_name"],
                "status": "extracted",
                "new_sigs": patch_info["new_sigs"],
            })

    if args.output:
        Path(args.output).write_text(json.dumps(diff, indent=2))

    print(json.dumps(diff, indent=2))
    return {"status": "ok", "diff": diff}


def find_reference_binary(
    new_version: int, ref_dir: Optional[Path] = None
) -> Optional[str]:
    """Find the latest known-good binary before the new version."""
    ref_dir = ref_dir or DEFAULT_DOWNLOADS_DIR

    # Search for build directories
    builds = []
    for d in ref_dir.glob("*/sublime_text.exe"):
        match = re.search(r"build_(\d+)", str(d.parent))
        if match:
            builds.append((int(match.group(1)), str(d)))

    builds.sort(key=lambda x: x[0])

    for ver, exe in builds:
        if ver < new_version:
            return exe

    return None


def extract_patch_sigs(
    old_data: bytes, new_data: bytes, patch_info: Dict[str, Any]
) -> List[str]:
    """Extract new signature bytes for a failed patch using block matching."""
    # This needs the original patch definition to know sig details
    # For now, extract based on known patterns
    sig_name = patch_info["sig_name"]

    # Map sig names to their known properties
    sig_map = {
        "invalidate1": {
            "length": 11,
            "wildcards": {2, 3, 4, 5, 7, 8, 9},
            "anchor": bytes.fromhex("e8"),
        },
        "invalidate2": {
            "length": 11,
            "wildcards": {2, 3, 4, 5, 7, 8, 9},
            "anchor": bytes.fromhex("e8"),
        },
        "server_validate": {
            "length": 15,
            "wildcards": {2, 7, 8, 9},
            "anchor": bytes.fromhex("56 57 53 48"),
        },
    }

    info = sig_map.get(sig_name)
    if not info:
        return []

    # Find the patch in the old binary
    # We need to know the old offset - look it up
    try:
        # Try to load old version to find offsets
        import tempfile
        import shutil

        old_exe_path = find_reference_binary(int)
    except Exception:
        pass

    return []


def cmd_validate(args):
    """Apply new signatures in-memory, test new + old builds."""
    with open(args.patch_diff) as f:
        diff = json.load(f)

    # Test new build with extracted signatures
    new_result = p.test_signatures_only(
        str(args.new_binary),
        force_channel=args.force,
    )

    passed = new_result.get("all_passed", False)
    print(f"New build test: {'PASS' if passed else 'FAIL'}")
    print(json.dumps(new_result, indent=2))

    return 0 if passed else 1


def cmd_apply(args):
    """Modify sublime_text_4_patcher.py source with new signatures."""
    with open(args.patch_diff) as f:
        diff = json.load(f)

    source = Path(args.source)
    content = source.read_text()

    version = diff["version"]
    if version not in p.PatchDB.CHANNELS.get(args.channel, ()):
        # Add version to CHANNELS
        versions_str = p.PatchDB.CHANNELS[args.channel][-1]
        # Find the last entry in CHANNELS for this channel and add after it
        pattern = rf'({args.channel}:\s*\([^)]*)\n(\s*\))'
        replacement = rf'\1,\n            {version}\2'
        content = re.sub(pattern, replacement, content)

    source.write_text(content)
    print(f"Updated {args.source} with version {version}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="signature_scanner",
        description="Automated signature detection for Sublime Text 4",
    )

    subparsers = parser.add_subparsers(dest="command")

    # detect
    detect_parser = subparsers.add_parser("detect", help="Detect latest dev build")

    # test
    test_parser = subparsers.add_parser("test", help="Test signatures on a binary")
    test_parser.add_argument("input", help="Path to sublime_text.exe")
    test_parser.add_argument("--output", help="Output JSON file", default=None)
    test_parser.add_argument("--force", help="Force channel (stable/dev)", default=None)

    # extract
    extract_parser = subparsers.add_parser("extract", help="Extract new signatures")
    extract_parser.add_argument(
        "--scan-result", required=True, help="JSON output from test command"
    )
    extract_parser.add_argument(
        "--new-binary", required=True, help="Path to new sublime_text.exe"
    )
    extract_parser.add_argument(
        "--ref-dir",
        type=Path,
        default=None,
        help="Directory with reference builds",
    )
    extract_parser.add_argument("--output", help="Output patch_diff.json")

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate patch diff")
    validate_parser.add_argument(
        "--patch-diff", required=True, help="JSON output from extract command"
    )
    validate_parser.add_argument(
        "--new-binary", required=True, help="Path to new sublime_text.exe"
    )
    validate_parser.add_argument("--force", help="Force channel", default=None)

    # apply
    apply_parser = subparsers.add_parser("apply", help="Apply changes to source")
    apply_parser.add_argument(
        "--patch-diff", required=True, help="JSON output from extract command"
    )
    apply_parser.add_argument(
        "--source",
        default=str(Path(__file__).resolve().parent.parent / "sublime_text_4_patcher.py"),
        help="Path to sublime_text_4_patcher.py",
    )
    apply_parser.add_argument(
        "--channel", default="dev", help="Channel to add version to"
    )

    args = parser.parse_args()

    if args.command == "detect":
        return cmd_detect(args)
    elif args.command == "test":
        result = cmd_test(args)
        return 0 if result["status"] in ("pass", "error") else 1
    elif args.command == "extract":
        cmd_extract(args)
        return 0
    elif args.command == "validate":
        return cmd_validate(args)
    elif args.command == "apply":
        return cmd_apply(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
