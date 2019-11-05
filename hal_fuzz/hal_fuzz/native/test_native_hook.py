#!/usr/bin/env python3
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.arm_const import *
import ctypes
import os
import sys
from os import path

uc_engine = ctypes.c_void_p
# Prototyping code taken from unicorn python bindings
def _load_lib(path):
    try:

        lib_file = os.path.join(path)
        #print('Trying to load shared library', lib_file)
        dll = ctypes.cdll.LoadLibrary(lib_file)
        #print('SUCCESS')
        return dll
    except OSError as e:
        #print('FAIL to load %s' %lib_file, e)
        return None

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

def exit_callback(status, other=None):
    print("exit_callback called with status {}, other={}".format(status, other))

EXIT_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_int, ctypes.c_int
)


# code to be emulated
ARM_CODE   = b"\x37\x00\xa0\xe3\x03\x10\x42\xe0" # mov r0, #0x37; sub r1, r2, r3
THUMB_CODE = b"\x83\xb0" # sub    sp, #0xc
# memory address where emulation starts
ADDRESS    = 0x10000


# callback for tracing basic blocks
#def hook_block(uc, address, size, user_data):
#    print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


def test_thumb(native_lib, file_path):
    print("Emulate THUMB code")
    try:
        # Initialize emulator in thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, THUMB_CODE)

        # initialize machine registers
        mu.reg_write(UC_ARM_REG_SP, 0x1234)

        # tracing all basic blocks with customized callback
        #mu.hook_add(UC_HOOK_BLOCK, hook_block)
        
        cb = ctypes.cast(EXIT_CB(exit_callback), EXIT_CB)
        assert(native_lib.init(mu._uch, cb)==0)
        assert(native_lib.load_fuzz(file_path.encode())==0)

        assert(native_lib.add_mmio_region(mu._uch, 0x1000, 0x2000)==0)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        # Note we start at ADDRESS | 1 to indicate THUMB mode.
        mu.emu_start(ADDRESS | 1, ADDRESS + len(THUMB_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        sp = mu.reg_read(UC_ARM_REG_SP)
        print(">>> SP = 0x%x" %sp)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} <input_file>".format(sys.argv[0]))
        exit(-1)

    file_path = sys.argv[1]
    own_path = os.path.dirname(os.path.realpath(__file__))
    native_lib = _load_lib(path.join(own_path, "./native_hooks.so"))
    _setup_prototype(native_lib, "init", ctypes.c_int, uc_engine, ctypes.c_void_p)
    _setup_prototype(native_lib, "load_fuzz", ctypes.c_int, ctypes.c_char_p)
    # uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end) {
    _setup_prototype(native_lib, "add_mmio_region", ctypes.c_int, uc_engine, ctypes.c_uint64, ctypes.c_uint64)
    test_thumb(native_lib, file_path)
