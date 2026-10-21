"""Run with python3 -m unittest discover -s tests/scripts -p test_convert_metallib.py."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('converter', Path(__file__).resolve().parents[2] / 'tools/convert-metallib.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MetalConversionTests(unittest.TestCase):
    def test_malformed_libraries_fail_closed(self):
        for data in (b'', b'MTLB' + bytes(83), b'MTLB' + bytes(84)):
            with self.assertRaises(ValueError):
                m.modules(data)
        data = bytearray(b'MTLB' + bytes(100))
        struct.pack_into('<QQ', data, 72, 88, 1000)
        with self.assertRaisesRegex(ValueError, 'bounds'):
            m.modules(data)

    def test_multiple_wrapped_modules_and_padding(self):
        module = struct.pack('<5I', 0x0B17C0DE, 0, 20, 4, 0) + b'BC\xc0\xde'
        data = bytearray(b'MTLB' + bytes(84))
        struct.pack_into('<QQ', data, 72, 88, len(module) * 2 + 8)
        data += module + bytes(8) + module
        self.assertEqual(m.modules(data), [module, module])
        data[88 + len(module)] = 1
        with self.assertRaisesRegex(ValueError, 'between'):
            m.modules(data)

    def test_real_device_air_keeps_shader_ir_symbols_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'shader.metal'
            source.write_text('#include <metal_stdlib>\nusing namespace metal;\nkernel void add(device float *p [[buffer(0)]], uint n [[thread_position_in_grid]]) { p[n] += 1.0f; }\n')
            air, lib = root / 'shader.air', root / 'default.metallib'
            m.run('metal', '-target', 'air64-apple-ios15.0', '-c', source, '-o', air)
            m.run('metallib', air, '-o', lib)
            self.assertIn('Platform: IOS\n', m.run('metal-objdump', '--metallib', '--all-headers', lib))
            self.assertEqual(m.convert(lib)['modules'], 1)
            self.assertIn('Platform: IOS (SIMULATOR)', m.run('metal-objdump', '--metallib', '--all-headers', lib))
            converted = lib.read_bytes()
            self.assertFalse(m.convert(lib)['converted'])
            self.assertEqual(lib.read_bytes(), converted)


if __name__ == '__main__':
    unittest.main()
