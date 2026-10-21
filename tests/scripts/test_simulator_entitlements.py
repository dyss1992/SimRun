import importlib.util
from pathlib import Path
import plistlib
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('entitlements', Path(__file__).resolve().parents[2] / 'tools/preserve-simulator-entitlements.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def image(first=4096):
    header = struct.pack('<8I', 0xFEEDFACF, 0x100000c, 0, 2, 2, 152 + 72, 0, 0)
    text = struct.pack('<II16s4Q4I', 0x19, 152, b'__TEXT', 0x100000000, 8192, 0, 8192, 5, 5, 1, 0)
    section = struct.pack('<16s16sQQ8I', b'__text', b'__TEXT', 0x100000000 + first, 16, first, 0, 0, 0, 0, 0, 0, 0)
    link = struct.pack('<II16s4Q4I', 0x19, 72, b'__LINKEDIT', 0x100002000, 4096, 8192, 4096, 1, 1, 0, 0)
    data = bytearray((header + text + section + link).ljust(12288, b'\0'))
    data[first:first + 16] = b'original-code!!!'
    return bytes(data)


class EntitlementsTests(unittest.TestCase):
    def test_preserves_all_original_sections_and_makes_metadata_readable(self):
        original = image()
        declarations = {'application-identifier': 'ABCDEFGHIJ.example.test', 'com.apple.security.application-groups': ['group.example.test']}
        converted = m.embed(original, declarations)
        self.assertEqual(len(converted), len(original))
        self.assertEqual(converted[4096:], original[4096:])
        self.assertEqual(struct.unpack_from('<I', converted, 20)[0], 304)
        # Original __text section unchanged; __LINKEDIT moves only within load commands.
        self.assertEqual(converted[104:184], original[104:184])
        self.assertEqual(converted[264:336], original[184:256])
        sec = 184
        self.assertEqual(converted[sec:sec + 16].rstrip(b'\0'), b'__entitlements')
        address, length, offset = struct.unpack_from('<QQI', converted, sec + 32)
        self.assertEqual(address, 0x100000000 + offset)
        self.assertEqual(plistlib.loads(converted[offset:offset + length]), declarations)
        self.assertEqual(m.embed(converted, {'other': True}), converted)

    def test_insufficient_or_nonzero_padding_fails_without_rewriting(self):
        with self.assertRaisesRegex(ValueError, 'padding'):
            m.embed(image(first=272), {'example': True})
        data = bytearray(image()); data[350] = 1
        with self.assertRaisesRegex(ValueError, 'padding'):
            m.embed(data, {'example': True})

    def test_later_section_ordinals_are_updated(self):
        data = bytearray(image())
        # Add __DATA with one section, then symbols and local relocations.
        segment = struct.pack('<II16s4Q4I', 0x19, 152, b'__DATA', 0x100002000, 4096, 8192, 4096, 3, 3, 1, 0)
        section = struct.pack('<16s16sQQ8I', b'__data', b'__DATA', 0x100002000, 16, 8192, 0, 9020, 4, 0, 0, 0, 0)
        symtab = struct.pack('<6I', 0x2, 24, 9000, 0, 0, 0)
        commands = data[32:184] + segment + section + symtab
        struct.pack_into('<II', data, 16, 3, len(commands))
        data[32:32 + len(commands)] = commands
        # One nlist_64 in __DATA; local relocation to __DATA plus three
        # non-section references that must stay unchanged.
        struct.pack_into('<I', data, 32 + 152 + 152 + 12, 1)
        struct.pack_into('<IBBHQ', data, 9000, 0, 0x0e, 2, 0, 0x100002000)
        cases = [(0, 2), (0, (1 << 27) | 2), (0, (10 << 28) | 2), (0x80000000, 2)]
        for i, pair in enumerate(cases):
            struct.pack_into('<II', data, 9020 + i * 8, *pair)
        converted = m.embed(data, {'example': True})
        self.assertEqual(converted[9005], 3)
        self.assertEqual(struct.unpack_from('<I', converted, 9024)[0], 3)
        for i, pair in enumerate(cases[1:], 1):
            self.assertEqual(struct.unpack_from('<II', converted, 9020 + i * 8), pair)

    def test_unsigned_device_build_needs_no_declarations(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp)
            (app / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable': 'App'}))
            executable = app / 'App'
            original = image()
            executable.write_bytes(original)
            self.assertFalse(m.preserve(app))
            self.assertEqual(executable.read_bytes(), original)

    def test_malformed_image_is_rejected(self):
        with self.assertRaises(ValueError):
            m.embed(b'', {'example': True})
        data = bytearray(image()); struct.pack_into('<I', data, 36, 0)
        with self.assertRaisesRegex(ValueError, 'load command'):
            m.embed(data, {'example': True})


if __name__ == '__main__':
    unittest.main()
