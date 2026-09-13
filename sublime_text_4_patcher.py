#! /usr/bin/env python3

# Credits to leogx9r for patching logic
# Script by rainbowpigeon


import argparse
import itertools
import logging
import re
from collections.abc import Sequence
from pathlib import Path
from sys import exit
from typing import NamedTuple, Optional, Union
from zipfile import ZipFile

import pefile

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
    def __init__(self, _bytes: bytes) -> None:
        self.bytes = _bytes

    def __str__(self) -> str:
        return "".join("\\x{:02x}".format(b) for b in self.bytes)

    def __format__(self, format_spec) -> str:
        return format(str(self), format_spec)


class Sig:
    # TODO: could consider combining consecutive expressions into one
    BYTE_RE = b".{1}"

    def __init__(self, pattern: str, ref: str = "", offset: int = 0x0, name: str = "") -> None:
        self.raw_pattern = pattern
        self.pattern = self.process_wildcards(self.raw_pattern)
        self.ref = ref
        self.offset = offset
        self.name = name

    def __str__(self) -> str:
        return f'"{self.name}": {self.raw_pattern}'

    @classmethod
    def process_wildcards(cls, pattern: str):
        return b"".join(
            re.escape(bytes.fromhex(byte)) if byte != "?" else cls.BYTE_RE
            for byte in pattern.split(" ")
        )


class Sigs(Sequence):
    """
    Contains multiple signatures as fallback options
    """

    def __init__(self, name: str, *sigs: Sig) -> None:
        self.sigs = sigs
        self.name = name
        if len(self.sigs) == 1:
            self.sigs[0].name = name
        else:
            # variants of original name
            for i, sig in enumerate(self.sigs):
                sig.name = f"{name}.{i + 1}"

    def __getitem__(self, index: Union[int, slice]):
        return self.sigs[index]

    def __len__(self) -> int:
        return len(self.sigs)

    def __str__(self) -> str:
        return self.name

    def __format__(self, format_spec) -> str:
        return format(str(self), format_spec)


class Patch:
    """
    Replaces bytes
    """

    # TODO: should consider other instruction forms and dynamically assemble
    CALL_LEN = 5  # E8 | xx xx xx xx
    LEA_LEN = 7  # 48 8D xx | xx xx xx xx

    patch_types = {
        k: bytes.fromhex(v)
        for k, v in {
            "nop": "90" * CALL_LEN,
            "ret": "C3",  # ret
            "ret0": "48 31 C0 C3",  # xor rax, rax; ret
            "ret1": "48 31 C0 48 FF C0 C3",  # xor rax, rax; inc rax; ret
            "ret280": "48 31 C0 B8 18 01 00 00 C3",  # xor rax, rax; mov eax, 280; ret
        }.items()
    }

    def __init__(self, patch_type: str, sigs: Union[Sig, Sigs]) -> None:
        # create Sigs for single Sig
        if isinstance(sigs, Sig):
            sigs = Sigs(sigs.name, sigs)
        self.sigs = sigs

        if patch_type not in Patch.patch_types:
            msg = f"Unsupported patch type {patch_type}"
            raise ValueError(msg)

        self.patch_type = patch_type
        self.new_bytes = Patch.patch_types[self.patch_type]
        self.patched = False

    def apply(self, file: "File"):
        logger.info("Applying patch %s...", self)
        for sig in self.sigs:
            logger.debug("Finding signature %s...", sig)
            try:
                self.offset = file.find(sig)
            except ValueError as e:
                logger.warning(e)
                continue
            else:
                end_offset = self.offset + len(self.new_bytes)
                # .data is a memoryview, so we need to make a copy of the old bytes
                self.old_bytes = file.data[self.offset : end_offset].tobytes()
                if self.old_bytes == self.new_bytes:
                    logger.warning("Patch %s has already been applied", self)
                self.log_patch(self.offset, sig.name, self.old_bytes, self.new_bytes)
                file.data[self.offset : end_offset] = self.new_bytes
                self.patched = True
                return self.offset
        msg = f"Could not find any signatures for patch {self}"
        raise ValueError(msg)

    def revert(self, file: "File"):
        logger.info("Reverting patch %s...", self)
        if not self.patched:
            msg = f"Patch {self} has not been applied"
            raise ValueError(msg)

        end_offset = self.offset + len(self.old_bytes)
        self.log_patch(self.offset, self.sigs, self.new_bytes, self.old_bytes)
        file.data[self.offset : end_offset] = self.old_bytes
        self.patched = False
        return self.offset

    @staticmethod
    def log_patch(offset, name, old_bytes, new_bytes) -> None:
        logger.debug(
            "Offset {:<8}: {}\n\t - {}\n\t + {}\n".format(
                hex(offset),
                name,
                PrettyBytes(old_bytes),
                PrettyBytes(new_bytes),
            )
        )

    def __str__(self) -> str:
        return f'"{self.patch_type} {self.sigs}"'


class File:
    """
    Loads file data
    """

    NULL = b"\x00"

    def __init__(self, filepath: Union[str, Path]) -> None:
        self.path = self.parse_path(filepath)
        self.pe = self.parse_pe()
        self.sections = {s.Name.strip(self.NULL).decode(): s for s in self.pe.sections}
        self.pe.close()

        try:
            self.data = memoryview(bytearray(self.path.read_bytes()))
        except OSError as e:
            msg = f"{self.path} is not a valid file"
            raise OSError(msg) from e
        else:
            self.patches: list[Patch] = []
            self.patched_offsets: list[int] = []

    def add_patch(self, patch: Patch) -> None:
        self.patches.append(patch)

    def add_patches(self, patches: list[Patch]):
        logger.info("Adding patches...")
        if not patches:
            logger.warning("No patches to add")
            return
        self.patches.extend(patches)

    def save(self) -> None:
        backup_path = self.path.with_suffix(f"{self.path.suffix}.bak")
        logger.info("Backing up original file at %s", backup_path)

        try:
            self.path.replace(backup_path)
        except PermissionError as e:
            msg = f"Permission denied renaming file to {backup_path}. Try running as Administrator"
            raise PermissionError(msg) from e
        except OSError as e:
            msg = f"Error renaming file to {backup_path}"
            raise OSError(msg) from e

        try:
            self.path.write_bytes(self.data)
        except PermissionError as e:
            msg = (
                f"Permission denied writing to new file {self.path}. Try running as Administrator."
            )
            raise PermissionError(msg) from e
        except OSError as e:
            msg = f"Error writing to new file {self.path}"
            raise OSError(msg) from e
        else:
            logger.info("Patched file written at %s", self.path)

    def apply_patch(self, patch: Patch):
        return patch.apply(self)

    def apply_all_patches(self):
        logger.info("Applying all patches...")
        if not self.patches:
            logger.warning("No patches to apply")
            return []
        for patch in self.patches:
            self.patched_offsets.append(self.apply_patch(patch))
        logger.info("All patches applied!")
        return self.patched_offsets

    def revert_patch(self, patch: Patch):
        return patch.revert(self)

    def revert_all_patches(self) -> None:
        logger.info("Reverting all patches...")
        if not self.patches:
            logger.warning("No patches to revert")
            return
        for patch in self.patches:
            self.revert_patch(patch)
        logger.info("All patches reverted!")

    @staticmethod
    def parse_path(filepath: Union[str, Path]):
        if isinstance(filepath, str):
            filepath = filepath.strip('"')
        path = Path(filepath)
        if not path.exists():
            msg = f"File {filepath} does not exist"
            raise FileNotFoundError(msg)
        if not path.is_file():
            logger.warning("%s is a directory, not a file", filepath)
            path = path / TARGET_PROGRAM
            logger.warning("Proceeding with assumed file path %s", path)
            if not path.exists():
                msg = f"File {path} does not exist"
                raise FileNotFoundError(msg)
            if not path.is_file():
                msg = f"{path} is a directory, not a file"
                raise FileNotFoundError(msg)
        return path

    def parse_pe(self):
        try:
            pe = pefile.PE(self.path, fast_load=True)
        except pefile.PEFormatError as e:
            msg = "Not a valid Windows application"
            raise pefile.PEFormatError(msg) from e

        if pe.NT_HEADERS.Signature != pefile.IMAGE_NT_SIGNATURE:
            msg = "Not a valid PE"
            raise pefile.PEFormatError(msg)

        if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            msg = "Not an x64 PE"
            raise pefile.PEFormatError(msg)

        if not pe.is_exe():
            msg = "Not a standard EXE"
            raise pefile.PEFormatError(msg)

        return pe

    # TODO: subclasses
    def find(self, pattern: Union[Sig, bytes]):
        if isinstance(pattern, Sig):
            return Finder(self).sig_find(pattern)
        if isinstance(pattern, bytes):
            return Finder(self).re_find(pattern)
        return None

    def find_string(self, pattern: Union[Sig, bytes]):
        if isinstance(pattern, Sig):
            return Finder(self).sig_find_string(pattern)
        if isinstance(pattern, bytes):
            return Finder(self).re_find_string(pattern)
        return None

    def __str__(self) -> str:
        return self.path


class SublimeText(File):
    VERSION_PATTERNS = tuple(
        r % rb"(\d{4})"
        for r in (
            b"version=%b",
            b"sublime_text_%b",
        )
    )

    def __init__(self, filepath: Union[str, Path]) -> None:
        super().__init__(filepath)

    def get_version(self):
        for pattern in self.VERSION_PATTERNS:
            try:
                version = self.find_string(pattern)
            except ValueError as e:
                logger.warning(e)
                continue
            else:
                return version.decode()
        msg = "Could not find version string"
        raise ValueError(msg)


class Ref:
    ADDR_LEN = 4

    def __init__(self, _type: str, total_size: int) -> None:
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
            Ref("lea", 7),  # 48 8D xx | xx xx xx xx
            Ref("jmp", 5),  # E9 | xx xx xx xx
        )
    }

    STR_SAMPLE_LEN = 100
    NULL = b"\x00"

    def __init__(self, file: "File") -> None:
        self.file = file

    def re_find(self, pattern: bytes):
        it = re.finditer(pattern, self.file.data, flags=re.DOTALL)
        match = next(it, None)
        if not match:
            msg = f"Could not find pattern {pattern!r}"
            raise ValueError(msg)
        if next(it, None):
            msg = f"Found multiple matches for pattern {pattern!r}"
            raise ValueError(msg)
        return match

    def re_find_string(self, pattern: bytes):
        return self.re_find(pattern).group(1)

    def sig_find(self, sig: Sig):
        try:
            match = self.re_find(sig.pattern)
        except ValueError as e:
            msg = f"Could not find signature {sig}"
            raise ValueError(msg) from e

        offset = match.start() + sig.offset

        if sig.ref:
            ref = self.ref_types.get(sig.ref)
            if not ref:
                msg = f"Unsupported reference type {sig.ref}"
                raise ValueError(msg)

            matched_bytes = match.group(0)
            matched_bytes = matched_bytes[sig.offset : sig.offset + ref.total_size]
            logger.debug("Resolving %s: %s", ref.type, PrettyBytes(matched_bytes))

            rel_addr = self.get_addr(ref, matched_bytes)
            logger.debug("Determined relative address: %s", hex(rel_addr))

            # TODO: handle different sections using off_to_rva + rva_to_off
            offset = offset + ref.total_size + rel_addr
            offset %= 2**32

            logger.debug("Determined actual offset: %s", hex(offset))

        return offset

    def sig_find_string(self, sig: Sig):
        offset = self.sig_find(sig)
        sample = self.file.data[offset : offset + self.STR_SAMPLE_LEN]
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
    def get_addr(ref: Ref, matched_bytes: bytes) -> int:
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
            4170,
            4171,
            4172,
            4173,
            4174,
            4175,
            4177,
            4178,
            4181,
            4183,
            4184,
            4185,
            4187,
            4188,
            4190,
            4191,
            4194,
            4195,
            4196,
            4198,
            4199,
            4205,
            4206,
            4207,
            4210,
            4211,
        ),
        "stable": (
            4107,
            4113,
            4121,
            4126,
            4142,
            4143,
            4151,
            4152,
            4166,
            4169,
            4180,
            4186,
            4189,
            4192,
            4200,
        ),
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

    def __init__(self, os, arch, version) -> None:
        try:
            self.channel = self.VERSIONS[version]
        except KeyError as e:
            msg = f"Version {version} does not exist in the patch database"
            raise KeyError(msg) from e
        if os not in self.OS:
            msg = f"Unsupported OS {os}"
            raise ValueError(msg)
        if arch not in self.ARCH:
            msg = f"Unsupported architecture {arch}"
            raise ValueError(msg)
        self.os = os
        self.arch = arch
        self.version = version
        self.DB = {
            os: {
                arch: {channel: () for channel in list(self.CHANNELS.keys()) + ["base"]}
                for arch in self.ARCH
            }
            for os in self.OS
        }
        self.load()

    def get_patches(self):
        return self.DB[self.os][self.arch]["base"] + self.DB[self.os][self.arch][self.channel]

    def load(self) -> None:
        if self.os == "windows":
            self.DB["windows"]["x64"]["base"] = (
                Patch(
                    # schedule callback 1
                    "nop",
                    Sig(
                        "41 B8 88 13 00 00 E8 ? ? ? ?",
                        offset=0x6,
                        name="license_revalidate1",
                    ),
                    # TODO: callback, ret
                    # TODO: license_invalidate callback, ret
                ),
                Patch(
                    # schedule callback 2
                    "nop",
                    Sig(
                        "41 B8 98 3A 00 00 E8 ? ? ? ?",
                        offset=0x6,
                        name="license_revalidate2",
                    ),
                    # TODO: callback, ret
                    # TODO: license_invalidate callback, ret
                ),
                Patch(
                    # valid enum
                    "ret280"
                    if self.version >= 4206
                    else "ret1"
                    if self.version == 4205
                    else "ret0",
                    Sigs(
                        "license_validate",
                        # callsite head
                        Sig(
                            "0f 11 ? ? ? 31 ? 45 31 ? 45 31 ? e8 ? ? ? ?",
                            ref="call",
                            offset=0xD,
                        ),
                        # callsite mid
                        Sig(
                            "45 31 ? e8 ? ? ? ? 85 c0 75 ? ? 8d",
                            ref="call",
                            offset=0x3,
                        ),
                        # callsite tail
                        Sig("e8 ? ? ? ? ? 8b ? ? ? ? ? 85 c0 0f 94 ? ? 74", ref="call"),
                        # TODO: other callsites
                    ),
                ),
                Patch(
                    # default
                    "ret0",
                    Sig(
                        "48 8d ? ? ? ? ? e8 ? ? ? ? 48 89 c1 ff ? ? ? ? ? ? 8b",
                        # thread
                        ref="lea",
                        name="online_license_notification",
                    ),
                ),
                Patch(
                    # CloseHandle
                    "ret1",
                    Sigs(
                        "online_license_check",
                        # thunk
                        Sig(
                            "8b 51 ? 48 83 c1 08 e9 ? ? ? ?",
                            ref="jmp",
                            offset=0x7,
                        ),
                        # thread creator
                        Sig(
                            "56 57 53 48 83 ec ? 89 d6 48 89 cf b9 ? 00 00 00 e8 ? ? ? ?",
                        ),
                        # TODO: thread, ret
                    ),
                ),
            )


class Result(NamedTuple):
    version: Optional[int] = None
    success: bool = False
    info: str = ""

    def __str__(self) -> str:
        status = "Success" if self.success else "Fail"
        return f"Version {self.version}: {status}: {self.info}"


def process_file(filepath, force_patch_channel=None):
    sublime = None
    try:
        sublime = SublimeText(filepath)
    except (OSError, FileNotFoundError, pefile.PEFormatError) as e:
        logger.exception(e)
        return Result(info=e)

    try:
        version = int(sublime.get_version())
    except ValueError as e:
        logger.exception(e)
        if not force_patch_channel:
            return Result(info=e)
        version = None
    else:
        logger.info("Sublime Text version %d detected", version)

    try:
        patches = PatchDB("windows", "x64", version).get_patches()
    except ValueError as e:
        logger.exception(e)
        return Result(info=e, version=version)
    except KeyError as e:
        logger.exception(e)
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

    sublime.add_patches(patches)

    try:
        offsets = sublime.apply_all_patches()
    except ValueError as e:
        logger.exception(e)
        return Result(info=e, version=version)

    try:
        sublime.save()
    except (OSError, PermissionError) as e:
        logger.exception(e)
        return Result(info=e, version=version)

    return Result(success=True, info=[hex(o) for o in sorted(offsets)], version=version)


def main() -> int:
    BORDER_LEN = 64

    description = f"Sublime Text v{PatchDB.MIN_SUPPORTED}-{PatchDB.MAX_SUPPORTED} Windows x64 Patcher by rainbowpigeon"
    epilog = "Report any issues at github.com/rainbowpigeon/sublime-text-4-patcher/issues!"

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
            with ZipFile(file) as zf:
                # overwrites without confirmation
                zf.extract(TARGET_PROGRAM, test_path / subdir)

        test_results = []
        for file in test_path.glob(f"./sublime_text_build_*_x64/{TARGET_PROGRAM}"):
            logger.info("Testing %s...", file)
            result = process_file(file, force_patch_channel)
            test_results.append(result)
            logger.info("-" * BORDER_LEN)
        for result in test_results:
            logger.info(result)

        return 0

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
