#!/usr/bin/env python3
"""Retarget a device AIR library for Simulator with Apple's installed Metal tools.

Only the LLVM target triple changes; shader instructions and metadata are checked
before publication. The caller must pass a disposable converted app, never its
original input. No source reconstruction or rendering substitutions are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def run(tool, *args):
    result = subprocess.run(["/usr/bin/xcrun", "--sdk", "iphonesimulator", tool, *map(str, args)],
                            capture_output=True, text=True)
    if result.returncode:
        raise ValueError(f"{tool}: {result.stderr.strip()}")
    return result.stdout


def modules(data):
    if len(data) < 88 or data[:4] != b"MTLB":
        raise ValueError("not an AIR metallib")
    start, size = struct.unpack_from("<QQ", data, 72)
    end = start + size
    if start < 88 or end > len(data):
        raise ValueError("invalid AIR module bounds")
    pos = start
    result = []
    while pos < end:
        if end - pos < 20:
            raise ValueError("truncated AIR wrapper")
        magic, version, offset, length, _ = struct.unpack_from("<5I", data, pos)
        if magic != 0x0B17C0DE or version != 0 or offset < 20 or pos + offset + length > end:
            raise ValueError("unsupported AIR wrapper")
        if data[pos + offset:pos + offset + 4] != b"BC\xc0\xde":
            raise ValueError("missing LLVM bitcode")
        result.append(data[pos:pos + offset + length])
        next_pos = data.find(b"\xde\xc0\x17\x0b", pos + offset + length, end)
        if next_pos < 0:
            if any(data[pos + offset + length:end]):
                raise ValueError("unrecognized trailing AIR data")
            break
        if any(data[pos + offset + length:next_pos]):
            raise ValueError("unrecognized data between AIR modules")
        pos = next_pos
    if not result:
        raise ValueError("empty AIR module list")
    return result


def ir_without_target(ir):
    return "\n".join(line for line in ir.splitlines()
                     if not line.startswith("; ModuleID =") and not line.startswith("target triple ="))


def convert(path):
    data = path.read_bytes()
    header = run("metal-objdump", "--metallib", "--all-headers", path)
    if "Platform: IOS\n" not in header:
        return {"path": str(path), "converted": False}
    if struct.unpack_from("<Q", data, 80)[0] == 0:
        # Empty placeholder library: no shader IR exists to relink.
        major = re.search(r"PlatformMajor: (\d+)", header)[1]
        run("metal-vtool", "--set-version-min", "ios-simulator", major + ".0", major + ".0", path)
        if "Platform: IOS (SIMULATOR)" not in run("metal-objdump", "--metallib", "--all-headers", path):
            raise ValueError("could not retarget empty library")
        return {"path": str(path), "converted": True, "modules": 0}
    original_modules = modules(data)
    with tempfile.TemporaryDirectory(prefix="simrun-metal-", dir=path.parent) as temp:
        work = Path(temp)
        retargeted = []
        for index, module in enumerate(original_modules):
            air, source, output = work / f"{index}.air", work / f"{index}.ll", work / f"{index}-sim.air"
            air.write_bytes(module)
            run("metal-opt", "-S", air, "-o", source)
            ir = source.read_text()
            match = re.search(r'^target triple = "(air64[^" ]*-apple-ios[0-9.]+)"$', ir, re.M)
            if not match:
                raise ValueError("unsupported AIR target triple")
            run("metal-opt", "--mtriple=" + match[1] + "-simulator", air, "-o", output)
            check = work / f"{index}-sim.ll"
            run("metal-opt", "-S", output, "-o", check)
            if ir_without_target(ir) != ir_without_target(check.read_text()):
                raise ValueError("retargeting changed shader IR beyond its target triple")
            retargeted.append(output)
        final = work / "converted.metallib"
        run("metallib", *retargeted, "-o", final)
        if "Platform: IOS (SIMULATOR)" not in run("metal-objdump", "--metallib", "--all-headers", final):
            raise ValueError("linker did not produce a Simulator library")
        # Re-linking may change metadata offsets, but exported shader names must match.
        before = run("metal-nm", path)
        after = run("metal-nm", final)
        if before != after:
            raise ValueError("exported shader symbols changed")
        final.chmod(path.stat().st_mode & 0o777)
        new_data = final.read_bytes()
        os.replace(final, path)
    return {"path": str(path), "converted": True, "modules": len(original_modules),
            "before": hashlib.sha256(data).hexdigest(), "after": hashlib.sha256(new_data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="a disposable converted .app or .metallib")
    args = parser.parse_args()
    paths = sorted(args.path.rglob("*.metallib")) if args.path.is_dir() else [args.path]
    for path in paths:
        print(json.dumps(convert(path)), flush=True)


if __name__ == "__main__":
    main()
