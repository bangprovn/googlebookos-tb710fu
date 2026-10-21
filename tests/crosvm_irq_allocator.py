#!/usr/bin/env python3
"""Execute only the pinned allocator in a sandboxed AArch64 CPU emulator.

Run inside a network-disabled, read-only container. No guest syscalls, extracted
program entrypoints, linker or host callbacks are executed. Requires Unicorn
2.1.4. Arguments: ORIGINAL ADAPTED. JSON goes to stdout.
"""
import hashlib
import json
import pathlib
import struct
import sys

import unicorn
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X8,
    UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_TPIDR_EL0,
)

ORIGINAL_SHA = "cc9f1e31025f2826ae050d025c363c885c0d055bff42c18701a2aa507c28fb52"
ENTRY = 0x45CFB8
LENGTH = 0x1B0
PATCH = 0x45D0B8
BASE = 0x2000000
STOP, BITS, MEMORY = BASE, BASE + 4, BASE + 8
VM, VTABLE, LAYOUT = BASE + 0x1000, BASE + 0x2000, BASE + 0x3000
MEM, REGION, OUT, TLS = BASE + 0x4000, BASE + 0x5000, BASE + 0x6000, BASE + 0x7000
PANICS = {0x45D104, 0x45D134, 0x45D14C, 0x45D158, 0x45D15C}


def run(blob, bits, end, count):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x45C000, 0x2000)
    uc.mem_write(ENTRY, blob[ENTRY:ENTRY + LENGTH])
    uc.mem_map(BASE, 0x20000)
    uc.mem_write(VTABLE + 0x38, struct.pack("<QQ", BITS, MEMORY))
    uc.mem_write(MEM, struct.pack("<QQ", REGION, count))
    uc.mem_write(REGION + 0x78, struct.pack("<QQ", 0, end))
    uc.mem_write(LAYOUT + 0x10, struct.pack("<QQ", 0x2C000000, 0x2DFFFFFF))
    uc.mem_write(OUT, bytes([0xA5]) * 0x58)
    uc.mem_write(TLS + 0x28, struct.pack("<Q", 0xABCDEF0123456789))
    for register, value in ((UC_ARM64_REG_X0, VM), (UC_ARM64_REG_X1, VTABLE),
                            (UC_ARM64_REG_X2, LAYOUT), (UC_ARM64_REG_X8, OUT),
                            (UC_ARM64_REG_SP, BASE + 0x1F000),
                            (UC_ARM64_REG_LR, STOP), (UC_ARM64_REG_TPIDR_EL0, TLS)):
        uc.reg_write(register, value)
    result = {"termination": None, "instructions": 0, "callbacks": []}

    def hook(machine, pc, size, _):
        result["instructions"] += 1
        if pc in (STOP, *PANICS):
            result["termination"] = "returned" if pc == STOP else f"panic:{pc:x}"
            machine.emu_stop()
        elif pc in (BITS, MEMORY):
            result["callbacks"].append("phys_bits" if pc == BITS else "guest_memory")
            machine.reg_write(UC_ARM64_REG_X0, bits if pc == BITS else MEM)
            machine.reg_write(UC_ARM64_REG_PC, machine.reg_read(UC_ARM64_REG_LR))
        elif not ENTRY <= pc < ENTRY + LENGTH:
            raise AssertionError(f"execution escaped allocator: {pc:x}")

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(ENTRY, BASE + 0x1FFFF, timeout=1_000_000, count=10000)
    assert result["termination"] is not None, "instruction/time limit reached"
    result["output"] = bytes(uc.mem_read(OUT, 0x58))
    return result


def main():
    assert unicorn.__version__ == "2.1.4", "pin the CPU emulator version"
    assert len(sys.argv) == 3
    images = []
    for name in sys.argv[1:]:
        path = pathlib.Path(name)
        assert path.is_file() and path.stat().st_size == 13_417_312
        with path.open("rb") as source:
            images.append(source.read(13_417_313))
    old, new = images
    assert hashlib.sha256(old).hexdigest() == ORIGINAL_SHA
    assert len(old) == len(new) == 13_417_312
    assert old[PATCH:PATCH + 4] == bytes.fromhex("88008052")
    assert new[PATCH:PATCH + 4] == bytes.fromhex("08028052")
    assert all(a == b or PATCH <= i < PATCH + 4 or 0x2E8 <= i < 0x2F8
               for i, (a, b) in enumerate(zip(old, new))), "unrelated mutation"
    cases = []
    for bits in (30, 32, 36, 40, 48, 63, 64):
        for end in (0, 512 << 20, 1 << 30, 2 << 30, 4 << 30, 0xFFFFFFFFFFFFFFFF):
            count = 0 if end == 0 else 1
            before, after = run(old, bits, end, count), run(new, bits, end, count)
            assert before["termination"] == after["termination"]
            assert before["callbacks"] == after["callbacks"]
            if before["termination"] == "returned":
                a, b = before["output"], after["output"]
                assert struct.unpack_from("<I", a, 0x50)[0] == 4
                assert struct.unpack_from("<I", b, 0x50)[0] == 16
                assert a[:0x50] == b[:0x50] and a[0x54:] == b[0x54:]
                assert struct.unpack_from("<QQQ", b, 0x18) == (1, end, end + 0x3FFFFFFF)
                assert struct.unpack_from("<QQ", b, 0x30) == (0x2C000000, 0x2DFFFFFF)
                high = end + 0x40000000
                assert struct.unpack_from("<QQ", b, 0x40) == (
                    (1, 0) if (1 << bits) == high else (high, (1 << bits) - 1))
            else:
                assert before["output"] == after["output"]
            cases.append({"phys_bits": bits, "memory_end": end, "regions": count,
                          "result": after["termination"], "instructions": after["instructions"]})
    print(json.dumps({"schema_version": 1, "status": "passed", "cases": cases,
                      "source_sha256": ORIGINAL_SHA, "output_sha256": hashlib.sha256(new).hexdigest(),
                      "emulator": "Unicorn 2.1.4", "syscalls_executed": False,
                      "scope": "pure allocator function only; no devices, kernel or hypervisor",
                      "hardware_verified": False}, indent=2))


if __name__ == "__main__":
    main()
