#! /usr/bin/env python3

# Credits to leogx9r for most signatures and patching logic
# Script by rainbowpigeon


import re
import pefile
import logging
import argparse
import itertools
from sys import exit
from pathlib import Path
from zipfile import ZipFile
from typing import NamedTuple, Union, Optional, List


TARGET_PROGRAM = "sublime_text.exe"


class SpecialFormatter(logging.Formatter):
    FORMATS = {
        logging.ERROR: "[!] %(message)s",
        logging.INFO: "[+] %(message)s",
        logging.DEBUG: "[=] %(message)s",
        logging.WARNING: "[-] %(message)s",
        "DEFAULT": "%(levelname)s: %(message)s",
    }

    def format(self, record: logging.LogRecord):
        orig_fmt = self._fmt
        orig_style = self._style

        self._fmt = self.FORMATS.get(record.levelno, self.FORMATS["DEFAULT"])
        self._style = logging.PercentStyle(self._fmt)
        result = super().format(record)

        self._fmt = orig_fmt
        self._style = orig_style

        return result


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
c_handler = logging.StreamHandler()
c_handler.setLevel(logging.DEBUG)
c_handler.setFormatter(SpecialFormatter())
logger.addHandler(c_handler)


class PrettyBytes:
    def __init__(self, _bytes: bytes):
        self.bytes = _bytes

    def __str__(self):
        return "".join("\\x{:02x}".format(b) for b in self.bytes)


class Sig:
    # TODO: could consider combining consecutive expressions into one
    BYTE_RE = b".{1}"

    def __init__(self, pattern: str, ref: str = "", offset: int = 0x0, name: str = ""):
        self.raw_pattern = pattern
        self.pattern = self.process_wildcards(self.raw_pattern)
        self.ref = ref
        self.offset = offset
        self.name = name

    def __str__(self):
        return f'"{self.name}": {self.raw_pattern}'

    @classmethod
    def process_wildcards(cls, pattern: str):
        return b"".join(
            re.escape(bytes.fromhex(byte)) if byte != "?" else cls.BYTE_RE
            for byte in pattern.split(" ")
        )


class Patch:
    """
    Replaces bytes
    """

    # TODO: should consider other instruction forms and dynamically assemble
    CALL_LEN = 5  # E8 | xx xx xx xx
    LEA_LEN = 7  # LEA: 48 8D xx | xx xx xx xx

    patch_types = {
        k: bytes.fromhex(v)
        for k, v in {
            "nop": "90" * CALL_LEN,
            "ret": "C3",  # ret
            "ret0": "48 31 C0 C3",  # xor rax, rax; ret
            "ret1": "48 31 C0 48 FF C0 C3",  # xor rax, rax; inc rax; ret
        }.items()
    }

    def __init__(self, sig: Sig, patch_type: str, file: Optional["File"] = None):
        self.sig = sig
        if file:
            self.file = file
            self.offset = Finder(self.file, self.sig).find()

        if patch_type not in Patch.patch_types:
            raise ValueError(f"Unsupported patch type {patch_type}")

        self.patch_type = patch_type
        self.new_bytes = Patch.patch_types[self.patch_type]

    def apply(self, file: Optional["File"] = None):
        if not hasattr(self, "file"):
            if not file:
                raise ValueError("No file provided")
            self.file = file
            self.offset = Finder(self.file, self.sig).find()
        end_offset = self.offset + len(self.new_bytes)
        logger.debug(
            "Offset {:<8}: {:<18}: patching {} with {}".format(
                hex(self.offset),
                self.sig.name,
                PrettyBytes(self.file.data[self.offset : end_offset]),
                PrettyBytes(self.new_bytes),
            )
        )
        self.file.data[self.offset : end_offset] = self.new_bytes
        return self.offset


class File:
    """
    Loads file data
    """

    NULL = b"\x00"

    def __init__(self, filepath: Union[str, Path]):
        self.path = self.parse_path(filepath)
        self.pe = self.parse_pe()
        self.sections = {s.Name.strip(self.NULL).decode(): s for s in self.pe.sections}
        self.pe.close()

        try:
            self.data = memoryview(bytearray(self.path.read_bytes()))
        except IOError as e:
            raise IOError(f"{self.path} is not a valid file") from e
        else:
            self.patches: List[Patch] = []
            self.patched_offsets: List[int] = []

    def create_patch(self, patch: Patch):
        patch.__init__(patch.sig, patch.patch_type, self)
        self.patches.append(patch)

    def save(self):
        backup_path = self.path.with_suffix(f"{self.path.suffix}.bak")
        logger.info("Backing up original file at %s", backup_path)

        try:
            self.path.replace(backup_path)
        except PermissionError as e:
            raise PermissionError(
                f"Permission denied renaming file to {backup_path}. Try running as Administrator"
            ) from e
        except IOError as e:
            raise IOError(f"Error renaming file to {backup_path}") from e

        try:
            self.path.write_bytes(self.data)
        except PermissionError as e:
            raise PermissionError(
                f"Permission denied writing to new file {self.path}. Try running as Administrator."
            ) from e
        except IOError as e:
            raise IOError(f"Error writing to new file {self.path}") from e
        else:
            logger.info("Patched file written at %s", self.path)

    def apply_all_patches(self):
        logger.info("Applying all patches...")
        for patch in self.patches:
            self.patched_offsets.append(patch.apply())
        logger.info("All patches applied!")
        return self.patched_offsets

    # TODO: could add apply_patch method

    def get_string(self, sig: Sig):
        return Finder(self, sig).get_string()

    @staticmethod
    def parse_path(filepath: Union[str, Path]):
        if isinstance(filepath, str):
            filepath = filepath.strip('"')
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File {filepath} does not exist")
        if not path.is_file():
            logger.warning("%s is a directory, not a file", filepath)
            path = path / TARGET_PROGRAM
            logger.warning("Proceeding with assumed file path %s", path)
            if not path.exists():
                raise FileNotFoundError(f"File {path} does not exist")
            if not path.is_file():
                raise FileNotFoundError(f"{path} is a directory, not a file")
        return path

    def parse_pe(self):
        try:
            pe = pefile.PE(self.path, fast_load=True)
        except pefile.PEFormatError as e:
            raise pefile.PEFormatError("Not a valid Windows application") from e

        if pe.NT_HEADERS.Signature != pefile.IMAGE_NT_SIGNATURE:
            raise pefile.PEFormatError("Not a valid PE")

        if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            raise pefile.PEFormatError("Not an x64 PE")

        if not pe.is_exe():
            raise pefile.PEFormatError("Not a standard EXE")

        return pe

    def __str__(self):
        return self.path


class Ref:
    ADDR_LEN = 4

    def __init__(self, _type: str, total_size: int):
        self.type = _type
        self.total_size = total_size
        self.op_size = self.total_size - self.ADDR_LEN


class Finder:
    """
    Determines correct offset
    """

    ref_types = {
        r.type: r
        for r in (
            Ref("call", 5),  # E8 | xx xx xx xx
            Ref("lea", 7),  # LEA: 48 8D xx | xx xx xx xx
        )
    }

    STR_SAMPLE_LEN = 100
    NULL = b"\x00"

    def __init__(self, file: File, sig: Sig):
        self.file = file
        self.sig = sig

        it = re.finditer(self.sig.pattern, self.file.data, flags=re.DOTALL)
        match = next(it, None)
        if not match:
            raise ValueError(f"Could not find signature {self.sig}")
        if next(it, None):
            raise ValueError(f"Found multiple matches for signature {self.sig}")

        self.offset = match.start() + self.sig.offset

        if self.sig.ref:
            ref = self.ref_types.get(self.sig.ref)
            if not ref:
                raise ValueError(f"Unsupported ref type {self.sig.ref}")

            logger.debug("Processing ref for signature %s...", self.sig)

            matched_bytes = match[0]
            logger.debug("Found %s: %s", ref.type, PrettyBytes(matched_bytes))

            matched_bytes = matched_bytes[self.sig.offset :]

            rel_addr = self.get_addr(ref, matched_bytes)
            logger.debug("Found relative address: %s", hex(rel_addr))

            if ref.type == "lea":
                self.offset = self.off_to_rva(self.offset, ".text")
                self.offset = self.offset + ref.total_size + rel_addr
                self.offset = self.rva_to_off(self.offset, ".rdata")
            else:
                self.offset = self.offset + ref.total_size + rel_addr

            self.offset %= 2**32

            logger.debug("Determined actual offset: %s", hex(self.offset))

    def find(self):
        return self.offset

    def get_string(self):
        sample = self.file.data[self.offset : self.offset + self.STR_SAMPLE_LEN]
        return sample[: sample.tobytes().find(self.NULL)].tobytes().decode()

    # TODO: could use functions from pefile instead
    def off_to_rva(self, value: int, section: str):
        return (
            value
            - self.file.sections[section].PointerToRawData
            + self.file.sections[section].VirtualAddress
        )

    def rva_to_off(self, value: int, section: str):
        return (
            value
            - self.file.sections[section].VirtualAddress
            + self.file.sections[section].PointerToRawData
        )

    @staticmethod
    def get_addr(ref: Ref, matched_bytes: bytes):
        rel_addr = matched_bytes[ref.op_size : ref.total_size]
        return int.from_bytes(rel_addr, byteorder="little")


class PatchDB:
    CHANNELS = {
        "dev": (
            4109,
            4110,
            4111,
            4112,
            4114,
            4115,
            4116,
            4117,
            4118,
            4119,
            4120,
            4122,
            4123,
            4124,
            4125,
            4127,
            4128,
            4129,
            4130,
            4131,
            4134,
            4136,
            4137,
            4138,
            4139,
            4140,
            4141,
            4145,
            4146,
            4147,
            4148,
            4149,
            4150,
            4153,
            4154,
            4155,
            4156,
            4158,
            4159,
            4160,
            4164,
            4165,
            4167,
            4168,
        ),
        "stable": (4107, 4113, 4121, 4126, 4142, 4143, 4151, 4152, 4166, 4169),
    }

    all_versions = tuple(itertools.chain.from_iterable(CHANNELS.values()))
    MIN_SUPPORTED = min(all_versions)
    MAX_SUPPORTED = max(all_versions)

    VERSIONS = {}
    for channel, versions in CHANNELS.items():
        for version in versions:
            VERSIONS[version] = channel

    OS = ("windows", "macos", "linux")
    ARCH = ("x64", "x86", "ARM64")

    def __init__(self, os, arch, version):
        try:
            self.channel = self.VERSIONS[version]
        except KeyError as e:
            raise KeyError(
                f"Version {version} does not exist in the patch database"
            ) from e
        if os not in self.OS:
            raise ValueError(f"Unsupported OS {os}")
        if arch not in self.ARCH:
            raise ValueError(f"Unsupported architecture {arch}")
        self.os = os
        self.arch = arch
        self.DB = {
            os: {
                arch: {channel: () for channel in list(self.CHANNELS.keys()) + ["base"]}
                for arch in self.ARCH
            }
            for os in self.OS
        }
        self.load()

    def get_patches(self):
        return (
            self.DB[self.os][self.arch]["base"]
            + self.DB[self.os][self.arch][self.channel]
        )

    def load(self):
        if self.os == "windows":
            self.DB["windows"]["x64"]["base"] = (
                Patch(
                    Sig(
                        "4C 8D 4D ? E8 ? ? ? ? ? 8B ? ? ? ? ? 85 C0",
                        ref="call",
                        offset=0x4,
                        name="license_check_ref",
                    ),
                    "ret0",
                ),
                Patch(
                    Sig(
                        "55 56 57 48 83 EC 30 48 8D 6C 24 ? 48 C7 45 ? ? ? ? ? 89 D6 48 89 CF 6A 28",
                        name="server_validate",
                    ),
                    "ret1",
                ),
                Patch(
                    Sig(
                        "55 56 57 48 81 EC ? 03 ? ? 48 8D AC 24 ? ? ? ?",
                        name="license_notify",
                    ),
                    "ret0",
                ),
                # TODO: investigate switch to crashpad in 4153
                # Patch(
                #     Sig(
                #         "41 57 41 56 41 55 41 54 56 57 55 53 B8 ? ? ? ? E8 ? ? ? ? 48 29 C4 8A 84 24 ? ? ? ?",
                #         name="crash_reporter",
                #     ),
                #     "ret",
                # ),
                Patch(
                    Sig(
                        "41 B8 88 13 00 00 E8 ? ? ? ?",
                        offset=0x6,
                        name="invalidate1_0x6",
                    ),
                    "nop",
                ),
                Patch(
                    Sig(
                        "41 B8 98 3A 00 00 E8 ? ? ? ?",
                        offset=0x6,
                        name="invalidate2_0x6",
                    ),
                    "nop",
                ),
            )


class Result(NamedTuple):
    version: Optional[int] = None
    success: bool = False
    info: str = ""

    def __str__(self):
        status = "Success" if self.success else "Fail"
        return f"Version {self.version}: {status}: {self.info}"


def process_file(filepath, force_patch_channel=None):
    sublime = None
    try:
        sublime = File(filepath)
    except (FileNotFoundError, pefile.PEFormatError, IOError) as e:
        logger.error(e)
        return Result(info=e)

    version_sig = "48 8D 05 ? ? ? ? 48 8D 95 ? ? ? ? 48 89 02 48 8D 05 ? ? ? ? 48 89 42 08 48 8D 4D ? E8 ? ? ? ? B9"
    version = Sig(version_sig, ref="lea", name="version")

    try:
        version = int(sublime.get_string(version))
    except ValueError as e:
        logger.error(e)
        logger.error("Failed to automatically detect version")
        return Result(info=e)
    else:
        logger.info("Sublime Text version %d detected", version)

    try:
        patches = PatchDB("windows", "x64", version).get_patches()
    except ValueError as e:
        logger.error(e)
        return Result(info=e, version=version)
    except KeyError as e:
        logger.error(e)
        if force_patch_channel:
            # try the latest version from the specified channel
            forced_version = PatchDB.CHANNELS[force_patch_channel][-1]
            logger.warning(
                f"Force patching as {force_patch_channel} version {forced_version} anyway..."
            )
            patches = PatchDB("windows", "x64", forced_version).get_patches()
        else:
            # TODO: prompt user to force patch
            logger.warning(
                "You can still use -f or manually add %d into PatchDB's CHANNELS dictionary if you would like to test it out",
                version,
            )
            return Result(info=e, version=version)

    try:
        for patch in patches:
            sublime.create_patch(patch)
    except ValueError as e:
        logger.error(e)
        return Result(info=e, version=version)

    offsets = sublime.apply_all_patches()

    try:
        sublime.save()
    except (IOError, PermissionError) as e:
        logger.error(e)
        return Result(info=e, version=version)

    return Result(success=True, info=[hex(o) for o in sorted(offsets)], version=version)


def main():
    BORDER_LEN = 64

    description = f"Sublime Text v{PatchDB.MIN_SUPPORTED}-{PatchDB.MAX_SUPPORTED} Windows x64 Patcher by rainbowpigeon"
    epilog = (
        "Report any issues at github.com/rainbowpigeon/sublime-text-4-patcher/issues!"
    )

    parser = argparse.ArgumentParser(
        prog=Path(__file__).name,
        description=description,
        epilog=epilog,
    )

    group = parser.add_mutually_exclusive_group()
    # optional positional argument
    group.add_argument("filepath", help=f"File path to {TARGET_PROGRAM}", nargs="?")
    group.add_argument(
        "-t",
        "--test",
        help="Directory path containing sublime_text_build_*_x64.zip files for batch testing",
        type=Path,
        metavar="DIRPATH",
    )
    parser.add_argument(
        "-f",
        "--force",
        help="Force patching even if detected Sublime Text version does not exist in the patch database",
        choices=["stable", "dev"],
    )
    args = parser.parse_args()
    filepath = args.filepath
    force_patch_channel = args.force
    test_path = args.test

    print("-" * BORDER_LEN)
    print(description)
    print("-" * BORDER_LEN)

    if test_path:
        logger.info("Testing using directory %s...", test_path)
        logger.info("-" * BORDER_LEN)

        if not test_path.exists():
            logger.error("Test directory %s does not exist", test_path)
            return 1

        if not test_path.is_dir():
            logger.error("Test path %s is not a directory", test_path)
            return 1

        for file in test_path.glob("./sublime_text_build_*_x64.zip"):
            subdir = file.stem
            with ZipFile(file) as zip:
                # overwrites without confirmation
                zip.extract(TARGET_PROGRAM, test_path / subdir)

        test_results = []
        for file in test_path.glob(f"./sublime_text_build_*_x64/{TARGET_PROGRAM}"):
            logger.info("Testing %s...", file)
            result = process_file(file, force_patch_channel)
            test_results.append(result)
            logger.info("-" * BORDER_LEN)
        for result in test_results:
            logger.info(result)

        return

    if not filepath:
        try:
            filepath = input(f"Enter file path to {TARGET_PROGRAM}: ")
        except KeyboardInterrupt:
            print()
            logger.warning("Exiting with KeyboardInterrupt")
            return 1

    result = process_file(filepath, force_patch_channel)

    if result.success:
        print("Enjoy! :)")
        print("-" * BORDER_LEN)
        print("IMPORTANT: Remember to enter any text as the license key!")
    print("-" * BORDER_LEN)
    print(epilog)
    print("-" * BORDER_LEN)

    return 0 if result.success else 1


if __name__ == "__main__":
    exit(main())
