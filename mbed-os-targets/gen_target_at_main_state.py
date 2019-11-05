#!/usr/bin/env python

from sys import argv
import os
import glob
import subprocess
import argparse
from os.path import join, isfile, isdir, split
import re

DIR=split(os.path.abspath(__file__))[0]
print(DIR)

OUT_FILE_NAME = "at_main_state.state"

def get_sym_from_readelf_output(output, sym):
    regex = "\\s*\\d+: ([0-9a-fA-F]+).*FUNC.* {}".format(sym)

    res = re.findall(regex, output.decode())
    if len(res) != 1:
        return None
    symbol = int(res[0], 16)
    return symbol
    

parser = argparse.ArgumentParser(description="Generate a state starting at the main function for a given target. Requires a single *.elf in the target directory as well as a set of input files")
parser.add_argument('target', help="Name of target to generate state for")
parser.add_argument('-i', '--relative-input-path', dest='rel_input_path', default="output/queue_min", help="Path relative to target base dir to use as input files")
parser.add_argument('-b', '--targets-base-dir', dest='targets_base_dir', default=DIR+"/targets" ,help="Path relative to target base dir to use as input files")
args = parser.parse_args()

target_dir = join(args.targets_base_dir, args.target)
config_path = join(target_dir, "config.yml")

if not isdir(target_dir):
    print("Could not find target dir: {}".format(target_dir))
    exit(1)

if not isfile(config_path):
    print("Could not find config dir: {}".format(target_dir))
    exit(2)

elfs = glob.glob(target_dir + "/*.elf")
if len(elfs) != 1:
    print("Did not find exactly one elf file. Found: {}".format(elfs))
    exit(3)
elf = elfs[0]

input_dir = join(target_dir, args.rel_input_path)

if not isdir(input_dir):
    print("Input dir '{}' does not exist".format(input_dir))
    exit(4)

readelf_output = subprocess.check_output(["readelf", "-s", elf])

bbl_addr = get_sym_from_readelf_output(readelf_output, "main")
if bbl_addr is None:
    print("Could not find symbol 'main' in elf file '{}'".format(elf))
    exit(5)
else:
    # Ensure alignment here
    bbl_addr &= (~1)

subprocess.check_call([DIR+"/../tracing/gen_reaching_state.sh", config_path, "0x{:x}".format(bbl_addr), input_dir, join(target_dir, OUT_FILE_NAME)])

exit(0)