# Credits to leogx9r for signatures and patching logic
# Script by rainbowpigeon

import re


class File():

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'rb') as file:
            self.data = bytearray(file.read())
        self.patches = []

    def create_patch(self, sig, patch_type):
        patch = Patch(self, sig, patch_type)
        self.patches.append(patch)

    def save(self):
        new_filename = self.filename + "_patched"
        with open(new_filename, "wb") as file:
            file.write(self.data)
        print("[+] Patched file written at {}".format(new_filename))

    def apply_all(self):
        print("[+] Applying all patches...")
        for patch in self.patches:
            patch.apply()
        print("[+] All patches applied")


class Patch():
    CALL_LEN = 5  # E8 xx xx xx xx

    patch_types = {
        "nop": "90" * CALL_LEN,
        "ret": "C3",  # ret
        "ret0": "48 31 C0 C3",  # xor rax, rax; ret
        "ret1": "48 31 C0 48 FF C0 C3",  # xor rax, rax; inc rax; ret
    }

    patch_types.update((k, bytes.fromhex(v)) for k, v in patch_types.items())

    def __init__(self, file, sig, patch_type):
        self.file = file

        self.sig = sig
        match = re.search(self.sig.pattern, self.file.data)
        self.offset = match.start() + self.sig.offset

        if self.sig.is_ref:
            print("[*] Processing ref for sig {}...".format(self.sig.pattern))

            call_bytes = match.group(0)
            print("[*] Found call: {}".format(call_bytes))

            rel_addr = self.get_addr_from_call(call_bytes)
            print("[*] Found Relative address: {}".format(hex(rel_addr)))

            self.offset = (self.offset + Patch.CALL_LEN + rel_addr) % (16 ** 8)
            print("[*] Determined function offset: {}".format(hex(self.offset)))

        assert patch_type in Patch.patch_types
        self.patch_type = patch_type
        self.new_bytes = Patch.patch_types[self.patch_type]

    def apply(self):
        print("[+] Offset: {}".format(hex(self.offset)))
        print("[+] Patching {} with {}".format(self.file.data[self.offset:self.offset + len(self.new_bytes)],
                                               self.new_bytes))
        self.file.data[self.offset:self.offset + len(self.new_bytes)] = self.new_bytes

    @staticmethod
    def bytes_to_int_LE(my_bytes):
        return int.from_bytes(my_bytes, byteorder='little')

    @classmethod
    def get_addr_from_call(cls, call_bytes):
        rel_addr = bytearray(call_bytes[1:Patch.CALL_LEN])  # E8 xx xx xx xx
        # rel_addr.hex()
        # rel_addr.reverse()
        return cls.bytes_to_int_LE(rel_addr)


class Sig:
    BYTE_RE = b".{1}"

    def __init__(self, pattern, is_ref=False, offset=0x0):
        self.pattern = self.process_wildcards(pattern)
        self.is_ref = is_ref
        self.offset = offset

    @classmethod
    def process_wildcards(cls, pattern):
        pattern = [re.escape(bytes.fromhex(byte)) if byte != "?" else cls.BYTE_RE for byte in pattern.split(" ")]
        return b"".join(pattern)


def main():
    print("-" * 64)
    print("Sublime Text v4113 Windows x64 Patcher by rainbowpigeon")
    print("-" * 64)

    sublime_file_path = input("Enter path to sublime_text.exe: ")

    sublime = File(sublime_file_path)

    # invalidate pattern for 4109, 4110, 4111, 4112
    #   Windows x64 Pattern 1: `direct reference sig: (+0x6) 41 B8 ? ? ? ? E8 ? ? ? ? 48 8B 96 ? ? ? ?`
    #            Pattern 2: `direct reference sig: (+0x6) 41 B8 ? ? ? ? E8 ? ? ? ? E8 ? ? ? ? 48 89 F1 `

    # sigs below for 4107, 4113

    # ret 0
    license_check_ref_sig = "E8 ? ? ? ? 48 8B 8B ? ? ? ? 85 C0"

    # NOP the calls
    invalidate1_0x6_sig = "41 B8 ? ? ? ? E8 ? ? ? ? 49 8B 96"
    invalidate2_sig = "E8 ? ? ? ? E8 ? ? ? ? 4C 89 F1 E8"

    # ret 1
    server_validate_sig = "55 56 57 48 83 EC 30 48 8D 6C 24 ? 48 C7 45 ? ? ? ? ? 89 D6 48 89 CF 6A 28"

    # ret 0
    license_notify_sig = "55 56 57 48 81 EC ? ? ? ? 48 8D AC 24 ? ? ? ? 0F 29 B5 ? ? ? ? 48 C7 85 ? ? ? ? ? ? ? ? 48 89 CF"

    # ret
    crash_reporter_sig = "41 57 41 56 41 55 41 54 56 57 55 53 B8 ? ? ? ? E8 ? ? ? ? 48 29 C4 8A 84 24 ? ? ? ?"

    license_check = Sig(license_check_ref_sig, is_ref=True)
    invalidate1 = Sig(invalidate1_0x6_sig, is_ref=False, offset=0x6)
    invalidate2 = Sig(invalidate2_sig)
    server_validate = Sig(server_validate_sig)
    license_notify = Sig(license_notify_sig)
    crash_reporter = Sig(crash_reporter_sig)

    sublime.create_patch(license_check, "ret0")
    sublime.create_patch(invalidate1, "nop")
    sublime.create_patch(invalidate2, "nop")
    sublime.create_patch(server_validate, "ret1")
    sublime.create_patch(license_notify, "ret0")
    sublime.create_patch(crash_reporter, "ret")

    sublime.apply_all()

    sublime.save()

    print("-" * 64)
    print("Report any issues at github.com/rainbowpigeon!")
    print("-" * 64)


if __name__ == "__main__":
    main()
