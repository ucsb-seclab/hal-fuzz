#!/usr/bin/env python2

base_config_fmt="""include:
  - ./../../../configs/hw/cortexm_memory.yml

architecture: arm
entry_point: 0x{:08x}
initial_sp: 0x{:08x}

use_nvic: False
use_timers: False

memory_map:
  text: {{base_addr: 0x{:08x}, file: ./basic_exercises.bin,
    permissions: r-x, size: 0x800000}}"""

from sys import argv
from os.path import isfile
from struct import unpack
from subprocess import check_output
import re

if len(argv) != 2:
    print("Usage: {} <foo.elf or foo.bin>")
    exit(0)

if argv[1].endswith(".elf"):
    elf_path = argv[1]
    bin_path = argv[1][:-3] + "bin"
elif argv[1].endswith(".bin"):
    elf_path = argv[1][:-3] + "elf"
    bin_path = argv[1]
else:
    print("nope")
    exit(-1)

if not (isfile(elf_path) and isfile(bin_path)):
    print("Can not find file '{}' or '{}'".format(elf_path, bin_path))
    exit(-1)

with open(bin_path, "rb") as f:
    initial_sp, entrypoint = unpack("<II", f.read(8))

regex = re.compile(r".*.text\s+PROGBITS\s+([0-9a-fA-F]{8}).*")
out = check_output(["readelf", "-S", elf_path])

res = regex.findall(out)
base_addr = int(res[0], 16)

print(base_config_fmt.format(entrypoint, initial_sp, base_addr))