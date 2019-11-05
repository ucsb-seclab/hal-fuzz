#!/usr/bin/env python3

import os
import re
import sys
import struct
from binascii import unhexlify
from unicorn.arm_const import *

reg_list = [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4,
            UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
            UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_SP, UC_ARM_REG_XPSR]

print("TODO: adjust to current snapshot format")
exit(-1)

def load_snapshot(file):
    reg_regex = re.compile(r"^[^=]{2,4}=0x([0-9a-f]+)$")

    res = {}
    for _ in reg_list:
        line = file.readline()
        print("Line: '{}'".format(line.rstrip()))
        val = int(reg_regex.match(line).group(1), 16)
        print("Got reg val: 0x{:x}".format(val))

    for line in file.readlines():
        addr = int(line[:10], 16)
        contents = unhexlify(line[11:-1])
        print("Restoring 0x{:x} bytes of contents to 0x{:08x}".format(len(contents), addr))
        res[addr] = contents

    return res

def get_value(regions, wanted):
    for addr, content in regions.items():
        if addr <= wanted < addr + len(content) - 4:
            return struct.unpack("<I", content[wanted-addr:wanted-addr+4])[0]

    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} <path>".format(sys.argv[0]))
        exit(-1)
    
    path = sys.argv[1]
    
    content_map = {}
    filenames = []

    if os.path.isfile(path):
        # Single file
        filenames=[path]
    
    elif not os.path.isdir(path):
        print("Path {} is neither file nor directory".format(path))
    else:
        # Directory
        filenames = [os.path.join(path, p) for p in os.listdir(path) if os.path.isfile(os.path.join(path, p))]

    for filename in filenames:
        with open(filename, "r") as f:
            content_map[filename] = load_snapshot(f)

    print("Loaded snapshot(s) for, any questions?")

    # Now enter interactive query loop
    while True:
        try:
            try:
                tokens = input("> ").split(" ")
                base = int(tokens[0], 16)
                if len(tokens) > 1:
                    num_vals = int(tokens[1])
                else:
                    num_vals = 1
            except ValueError:
                print("Please provide input in the form <hex_address> [num_vals=1]")

            for state_file, contents in content_map.items():
                for i in range(num_vals):
                    addr = base + 4 * i
                    val = get_value(contents, addr)
                    if len(content_map) != 1:
                        print("{}:".format(state_file))
                    print("0x{:08x}: 0x{:08x}".format(addr, val))

        except KeyboardInterrupt:
            print("Bye")
            exit(0)
