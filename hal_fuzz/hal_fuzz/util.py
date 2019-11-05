import struct
import signal
import os
from unicorn.arm_const import *
from unicorn.unicorn import UcError
from . import globs

def bytes2int(bs):
    if len(bs) == 4:
        return struct.unpack("<I", bs)[0]
    elif len(bs) == 2:
        return struct.unpack("<H", bs)[0]
    elif len(bs) == 1:
        return struct.unpack("<B", bs)[0]
    elif len(bs) == 8:
        return struct.unpack("<Q", bs)[0]
    else:
        from binascii import hexlify
        print("Can not unpack {} bytes: {}".format(len(bs), hexlify(bs)))
        assert(False)


def int2bytes(i):
    return struct.pack("<I", i)


def crash(sig=signal.SIGSEGV):
    print("-------------------------------- CRASH DETECTED-------------------------")
    os.kill(os.getpid(), sig)


def ensure_rw_mapped(uc, start, end):
    start = start & (~0xfff)
    end = (end + 0xfff) & (~0xfff)
    if start == end:
        end += 0x1000

    if all([start < rstart or end > rstart + size for rstart, size, _ in globs.regions.values()]):
        print("Adding mapping {:08x}-{:08x} because of a configured mmio model".format(start, end))
        globs.regions['mmio_model_region_{:x}_{:x}'.format(start, end)] = (start, end-start, 3)
        uc.mem_map(start, end-start, 3)
