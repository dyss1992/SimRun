#!/usr/bin/env python3
"""Keep device entitlement declarations in Xcode's Simulator metadata section.

The ad-hoc host signature still carries no restricted entitlements. This only
preserves the app's original declarations for Simulator frameworks; it cannot
grant access to host services or create an account/provisioning profile.
"""
import argparse
import json
from pathlib import Path
import plistlib
import struct
import subprocess


def embed(data, declarations):
    data = bytearray(data)
    if len(data) < 32 or struct.unpack_from('<I', data)[0] != 0xFEEDFACF:
        raise ValueError('expected a thin 64-bit Mach-O')
    count, size = struct.unpack_from('<II', data, 16)
    if 32 + size > len(data):
        raise ValueError('invalid load-command bounds')
    pos, first, text = 32, len(data), None
    ordinal, symtabs, relocations = 0, [], []
    for _ in range(count):
        if pos + 8 > 32 + size:
            raise ValueError('truncated load command')
        cmd, length = struct.unpack_from('<II', data, pos)
        if length < 8 or pos + length > 32 + size:
            raise ValueError('invalid load command')
        if cmd == 0x19:
            if length < 72:
                raise ValueError('truncated segment')
            sections = struct.unpack_from('<I', data, pos + 64)[0]
            if 72 + sections * 80 > length:
                raise ValueError('invalid section table')
            if data[pos + 8:pos + 24].rstrip(b'\0') == b'__TEXT':
                text = (pos, length, sections, ordinal + sections)
            for j in range(sections):
                section = pos + 72 + j * 80
                if data[section:section + 16].rstrip(b'\0') == b'__entitlements':
                    return bytes(data)  # Existing Simulator metadata wins.
                relocation_offset, relocation_count = struct.unpack_from('<II', data, section + 56)
                relocations.append((relocation_offset, relocation_count))
                offset = struct.unpack_from('<I', data, section + 48)[0]
                if offset:
                    first = min(first, offset)
            ordinal += sections
        elif cmd == 0x2:
            if length < 24:
                raise ValueError('truncated symbol table command')
            symtabs.append(struct.unpack_from('<II', data, pos + 8))
        elif cmd == 0xb:
            if length < 80:
                raise ValueError('truncated dynamic symbol table command')
            relocations.extend([struct.unpack_from('<II', data, pos + 64),
                                struct.unpack_from('<II', data, pos + 72)])
        pos += length
    if pos != 32 + size or text is None:
        raise ValueError('invalid load-command layout or missing __TEXT')
    xml = plistlib.dumps(declarations)
    # No original section is shifted; only unused header padding is consumed.
    start = (first - len(xml)) & ~15
    if start < 32 + size + 80 or any(data[32 + size:first]):
        raise ValueError('not enough zero-filled header padding for Simulator entitlements')
    if ordinal >= 255:
        raise ValueError('no section ordinal available for entitlements')
    pos, length, sections, insert_after = text
    # Mach-O symbols and local relocations use one-based section ordinals.
    # Inserting a __TEXT section shifts the ordinals in later segments.
    for offset, count in symtabs:
        if offset + count * 16 > len(data):
            raise ValueError('invalid symbol table bounds')
        for index in range(count):
            field = offset + index * 16 + 5  # nlist_64.n_sect
            if data[field] > insert_after:
                data[field] += 1
    for offset, count in set(relocations):
        if offset + count * 8 > len(data):
            raise ValueError('invalid relocation bounds')
        for index in range(count):
            address, bits = struct.unpack_from('<II', data, offset + index * 8)
            # Scattered relocations carry addresses; external relocations carry
            # symbol indices; ARM64_RELOC_ADDEND carries an addend, not a section.
            if address & 0x80000000 or bits & (1 << 27) or bits >> 28 == 10:
                continue
            section_ordinal = bits & 0xffffff
            if section_ordinal > insert_after:
                struct.pack_into('<I', data, offset + index * 8 + 4,
                                 (bits & 0xff000000) | (section_ordinal + 1))
    vmaddr, _, fileoff, filesize = struct.unpack_from('<4Q', data, pos + 24)
    if start < fileoff or start + len(xml) > fileoff + filesize:
        raise ValueError('entitlements would lie outside __TEXT')
    insert = pos + length
    section = struct.pack('<16s16sQQIIIIIIII', b'__entitlements', b'__TEXT',
                          vmaddr + start - fileoff, len(xml), start, 0, 0, 0, 0, 0, 0, 0)
    data[insert + 80:32 + size + 80] = data[insert:32 + size]
    data[insert:insert + 80] = section
    struct.pack_into('<I', data, pos + 4, length + 80)
    struct.pack_into('<I', data, pos + 64, sections + 1)
    struct.pack_into('<I', data, 20, size + 80)
    data[start:start + len(xml)] = xml
    return bytes(data)


def preserve(bundle):
    info = plistlib.loads((bundle / 'Info.plist').read_bytes())
    executable = bundle / info['CFBundleExecutable']
    data = executable.read_bytes()
    # No signature means no declarations, not a failed conversion. Unmodified
    # unsigned device builds were already supported by the converter.
    if len(data) < 32:
        raise ValueError('truncated Mach-O')
    count, size = struct.unpack_from('<II', data, 16)
    pos, signed = 32, False
    for _ in range(count):
        if pos + 8 > min(32 + size, len(data)):
            raise ValueError('truncated load command')
        command, length = struct.unpack_from('<II', data, pos)
        if length < 8 or pos + length > min(32 + size, len(data)):
            raise ValueError('invalid load command')
        if command == 0x1d:
            if length < 16:
                raise ValueError('truncated signature command')
            offset, length_in_file = struct.unpack_from('<II', data, pos + 8)
            if offset + length_in_file > len(data):
                raise ValueError('invalid signature bounds')
            signed = length_in_file > 0
        pos += length
    if not signed:
        return False
    result = subprocess.run(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(executable)],
                            capture_output=True)
    xml = result.stdout
    if not xml.strip():
        if result.returncode:
            raise ValueError(f'cannot read original entitlements: {bundle.name}')
        return False
    declarations = plistlib.loads(xml[xml.index(b'<?xml'):])
    if not declarations:
        return False
    data = executable.read_bytes()
    converted = embed(data, declarations)
    if data != converted:
        executable.write_bytes(converted)
    return data != converted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app', type=Path)
    root = parser.parse_args().app
    bundles = [root] + sorted(p for p in root.rglob('*') if p.suffix in ('.app', '.appex', '.xpc') and p.is_dir())
    for bundle in bundles:
        print(json.dumps({'bundle': str(bundle), 'entitlementsEmbedded': preserve(bundle)}), flush=True)


if __name__ == '__main__':
    main()
