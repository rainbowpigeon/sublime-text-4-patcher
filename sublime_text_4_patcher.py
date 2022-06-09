#! /usr/bin/env python3

# Credits to leogx9r for signatures and patching logic
# Script by rainbowpigeon


import re
import pefile
import logging
import itertools
from sys import exit
from pathlib import Path


class SpecialFormatter(logging.Formatter):
    FORMATS = {
        logging.ERROR: "[!] %(message)s",
        logging.INFO: "[+] %(message)s",
        logging.DEBUG: "[=] %(message)s",
        logging.WARNING: "[-] %(message)s",
        "DEFAULT": "%(levelname)s: %(message)s",
    }

    def format(self, record):
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
    def __init__(self, _bytes):
        self.bytes = _bytes

    def __str__(self):
        return "".join("\\x{:02x}".format(b) for b in self.bytes)


class Sig:
    BYTE_RE = b".{1}"

    def __init__(self, pattern: str, ref: str = "", offset: int = 0x0):
        self.raw_pattern = pattern
        self.pattern = self.process_wildcards(self.raw_pattern)
        self.ref = ref
        self.offset = offset

    def __str__(self):
        return self.raw_pattern

    @classmethod
    def process_wildcards(cls, pattern: str):
        pattern = [
            re.escape(bytes.fromhex(byte)) if byte != "?" else cls.BYTE_RE
            for byte in pattern.split(" ")
        ]
        return b"".join(pattern)


class Patch:
    """
    Replaces bytes
    """

    CALL_LEN = 5  # E8 | xx xx xx xx
    LEA_LEN = 7  # LEA: 48 8D xx | xx xx xx xx

    patch_types = {
        "nop": "90" * CALL_LEN,
        "ret": "C3",  # ret
        "ret0": "48 31 C0 C3",  # xor rax, rax; ret
        "ret1": "48 31 C0 48 FF C0 C3",  # xor rax, rax; inc rax; ret
    }

    patch_types.update((k, bytes.fromhex(v)) for k, v in patch_types.items())

    def __init__(self, sig: Sig, patch_type: str, file=None):
        self.sig = sig
        if file:
            self.file = file
            self.offset = Finder(self.file, self.sig).locate()

        if patch_type not in Patch.patch_types:
            raise ValueError(f"Unsupported patch type {patch_type}")

        self.patch_type = patch_type
        self.new_bytes = Patch.patch_types[self.patch_type]

    def apply(self, file=None):
        if not hasattr(self, "file"):
            if not file:
                raise ValueError("No file provided")
            self.file = file
            self.offset = Finder(self.file, self.sig).locate()
        end_offset = self.offset + len(self.new_bytes)
        logger.debug(
            "Offset {:<8}: patching {} with {}".format(
                hex(self.offset),
                PrettyBytes(self.file.data[self.offset : end_offset]),
                PrettyBytes(self.new_bytes),
            )
        )
        self.file.data[self.offset : end_offset] = self.new_bytes


class File:
    """
    Loads file data
    """

    SUBLIME_EXE_NAME = "sublime_text.exe"
    NULL = b"\x00"

    def __init__(self, filepath: str):
        self.filepath = filepath.strip('"')
        self.path = self.check_path()
        self.pe = self.parse_pe()
        self.sections = {s.Name.strip(self.NULL).decode(): s for s in self.pe.sections}
        self.pe.close()

        try:
            self.data = bytearray(self.path.read_bytes())
        except IOError as e:
            raise IOError(f"{self.path} is not a valid file") from e
        else:
            self.patches = []

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

        except IOError as exc:
            raise IOError(f"Error writing to new file {self.path}") from exc
        else:
            logger.info("Patched file written at %s", self.path)

    def apply_all(self):
        logger.info("Applying all patches...")
        for patch in self.patches:
            patch.apply()
        logger.info("All patches applied!")

    def get_string(self, sig: Sig):
        return Finder(self, sig).get_string()

    def check_path(self):
        path = Path(self.filepath)
        if not path.exists():
            raise FileNotFoundError(f"File {self.filepath} does not exist")
        if not path.is_file():
            logger.warning("%s is a directory, not a file", self.filepath)
            path = path / self.SUBLIME_EXE_NAME
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

        if pe.NT_HEADERS.Signature != 0x4550:
            raise pefile.PEFormatError("Not a valid PE")

        if pe.FILE_HEADER.Machine == 0x14C:
            raise pefile.PEFormatError("32 bit Sublime Text not supported")
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

    ref_types = [
        Ref("call", 5),  # E8 | xx xx xx xx
        Ref("lea", 7),  # LEA: 48 8D xx | xx xx xx xx
    ]

    ref_types = {r.type: r for r in ref_types}

    STR_SAMPLE_LEN = 100
    NULL = b"\x00"

    def __init__(self, file: File, sig: Sig):
        self.file = file
        self.sig = sig
        match = re.search(self.sig.pattern, self.file.data, flags=re.DOTALL)
        if not match:
            raise ValueError(f"Could not find signature: {self.sig}")

        self.offset = match.start() + self.sig.offset

        if self.sig.ref:
            ref = self.ref_types.get(self.sig.ref)
            if not ref:
                raise ValueError(f"Unsupported ref type {self.sig.ref}")

            logger.debug("Processing ref for sig %s...", self.sig)

            matched_bytes = match[0]
            logger.debug("Found %s: %s", ref.type, PrettyBytes(matched_bytes))

            matched_bytes = matched_bytes[self.sig.offset :]

            rel_addr = self.get_addr(ref, matched_bytes)
            logger.debug("Found relative address: %s", hex(rel_addr))

            if ref.type == "lea":
                self.offset = self.off_to_rva(".text")
                self.offset = (self.offset + ref.total_size + rel_addr) % (16**8)
                self.offset = self.rva_to_off(".rdata")
            else:
                self.offset = (self.offset + ref.total_size + rel_addr) % (16**8)

            logger.debug("Determined actual offset: %s", hex(self.offset))

    def locate(self):
        return self.offset

    def get_string(self):
        sample = self.file.data[self.offset : self.offset + self.STR_SAMPLE_LEN]
        return sample[: sample.find(self.NULL)].decode()

    def off_to_rva(self, section: str):
        return (
            self.offset
            - self.file.sections[section].PointerToRawData
            + self.file.sections[section].VirtualAddress
        )

    def rva_to_off(self, section: str):
        return (
            self.offset
            - self.file.sections[section].VirtualAddress
            + self.file.sections[section].PointerToRawData
        )

    @staticmethod
    def bytes_to_int_LE(_bytes):
        return int.from_bytes(_bytes, byteorder="little")

    @classmethod
    def get_addr(cls, ref: Ref, matched_bytes):
        rel_addr = bytearray(matched_bytes[ref.op_size : ref.total_size])
        # rel_addr.hex()
        # rel_addr.reverse()
        return cls.bytes_to_int_LE(rel_addr)


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
        ),
        "stable": (4107, 4113, 4121, 4126),
    }

    all_versions = tuple(itertools.chain.from_iterable(CHANNELS.values()))
    MIN_SUPPORTED = min(all_versions)
    MAX_SUPPORTED = max(all_versions)

    VERSIONS = {}
    for channel, versions in CHANNELS.items():
        for version in versions:
            VERSIONS[version] = channel

    OS = ("windows", "macos", "linux")
    ARCH = ("x64", "x86")

    def __init__(self, os, arch, version):
        self.DB = {os: {arch: {} for arch in self.ARCH} for os in self.OS}
        self.os = os
        self.arch = arch
        self.channel = self.VERSIONS.get(version)
        self.load()

    def get_patches(self):
        return dict(
            self.DB[self.os][self.arch][self.channel],
            **self.DB[self.os][self.arch]["base"],
        )

    def load(self):
        if self.os == "windows":
            self.DB["windows"]["x64"]["base"] = {
                "license_check_ref": Patch(
                    Sig(
                        "4C 8D 4D ? E8 ? ? ? ? ? 8B ? ? ? ? ? 85 C0",
                        ref="call",
                        offset=0x4,
                    ),
                    "ret0",
                ),
                "server_validate": Patch(
                    Sig(
                        "55 56 57 48 83 EC 30 48 8D 6C 24 ? 48 C7 45 ? ? ? ? ? 89 D6 48 89 CF 6A 28"
                    ),
                    "ret1",
                ),
                "license_notify": Patch(
                    Sig(
                        "55 56 57 48 81 EC ? ? ? ? 48 8D AC 24 ? ? ? ? 0F 29 B5 ? ? ? ? 48 C7 85 ? ? ? ? ? ? ? ? 48 89 CF"
                    ),
                    "ret0",
                ),
                "crash_reporter": Patch(
                    Sig(
                        "41 57 41 56 41 55 41 54 56 57 55 53 B8 ? ? ? ? E8 ? ? ? ? 48 29 C4 8A 84 24 ? ? ? ?"
                    ),
                    "ret",
                ),
            }

            self.DB["windows"]["x64"]["dev"] = {
                "invalidate1_0x6": Patch(
                    Sig("41 B8 ? ? ? ? E8 ? ? ? ? 48 8B 96 ? ? ? ?", offset=0x6), "nop"
                ),
                "invalidate2_0x6": Patch(
                    Sig("41 B8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 48 89 F1", offset=0x6),
                    "nop",
                ),
            }

            self.DB["windows"]["x64"]["stable"] = {
                "invalidate1_0x6": Patch(
                    Sig("41 B8 ? ? ? ? E8 ? ? ? ? 49 8B 96", offset=0x6), "nop"
                ),
                "invalidate2": Patch(Sig("E8 ? ? ? ? E8 ? ? ? ? 4C 89 F1 E8"), "nop"),
            }


def main():
    print("-" * 64)
    print(
        f"Sublime Text v{PatchDB.MIN_SUPPORTED}-{PatchDB.MAX_SUPPORTED} Windows x64 Patcher by rainbowpigeon"
    )

    print("-" * 64)

    sublime_file_path = None
    sublime = None

    try:
        sublime_file_path = input("Enter file path to sublime_text.exe: ")
    except KeyboardInterrupt:
        logger.warning("Exiting with KeyboardInterrupt")
        exit()

    try:
        sublime = File(sublime_file_path)
    except (FileNotFoundError, pefile.PEFormatError, IOError) as e:
        logger.error(e)
        exit(1)

    version_sig = "48 8D 05 ? ? ? ? 48 8D 95 ? ? ? ? 48 89 02 48 8D 05 ? ? ? ? 48 89 42 08 48 8D 4D ? E8 ? ? ? ? B9"
    version = Sig(version_sig, ref="lea")

    try:
        version = int(sublime.get_string(version))
    except ValueError as e:
        logger.error(e)
        logger.error("Failed to automatically detect version")
        exit(1)
    else:
        logger.info("Sublime Text Version %d detected", version)

    try:
        patches = PatchDB("windows", "x64", version).get_patches()
    except KeyError:
        logger.error("Version %d does not exist in the patch database", version)
        logger.error(
            "You can still manually add it into PatchDB's CHANNELS dictionary if you would like to test it out"
        )
        exit(1)

    for name, patch in patches.items():
        sublime.create_patch(patch)

    sublime.apply_all()

    try:
        sublime.save()
    except (IOError, PermissionError) as e:
        logger.error(e)
        exit(1)

    print("Enjoy! :)")
    print("-" * 64)
    print(
        "Report any issues at github.com/rainbowpigeon/sublime-text-4-patcher/issues!"
    )
    print("-" * 64)


if __name__ == "__main__":
    main()
