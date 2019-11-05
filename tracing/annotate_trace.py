#!/usr/bin/env python

from sys import argv
import argparse
import parse_trace
import cle
from os.path import basename, dirname, isfile

parser = argparse.ArgumentParser(description="Annotate a trace file with symbols from an ELF file using angr's CLE")
parser.add_argument('-e', '--elf', required=True, type=str, help="Path to the elf file to extract symbols from")
parser.add_argument('-o', dest='out_dir', required=True, type=str)
parser.add_argument('input_files', type=str, nargs="*", help="Path to the file containing the trace to annotate")

args = parser.parse_args()

elf = cle.Loader(args.elf)
func_syms = {addr: symbol for addr, symbol in elf.main_object.symbols_by_addr.items() if symbol.elftype == 'STT_FUNC' and symbol.relative_addr&1==1}

# print("[+] read {} lines".format(len(lines)))
# print("using out file path: {}".format(out_path))


# print("Got func syms: {}".format(func_syms))

func_off_cache = {}
def find_closest_func_and_off(addr):
    if addr not in func_off_cache:
        l = [func_addr for func_addr in func_syms if func_addr <= addr]
        if not l:
            return "unknown", 0

        closest_addr = max(l)
        sym = func_syms[closest_addr]

        func_off_cache[addr]=(sym.name, addr - sym.relative_addr)

    return func_off_cache[addr]

def gen_mmio_descr(line):
    event_id, pc, lr, mode, size, address, val_text = parse_trace.parse_mmio_line(line)

    pc_sym_name, pc_sym_func_off = find_closest_func_and_off(pc|1)
    lr_sym_name, lr_sym_func_off = find_closest_func_and_off(lr)

    descr = "pc: {}+{:x}\tlr: {}+{:x}".format(pc_sym_name, pc_sym_func_off, lr_sym_name, lr_sym_func_off)
    return descr

def gen_bb_descr(line):
    event_id, pc, cnt = parse_trace.parse_bb_line(line)

    pc_sym_name, pc_sym_func_off = find_closest_func_and_off(pc|1)

    descr = "pc: {}+{:x}".format(pc_sym_name, pc_sym_func_off)
    return descr


for input_trace_path in args.input_files:
    if not isfile(input_trace_path):
        continue
    
    with open(input_trace_path, "r") as f:
        lines = f.readlines()

    input_trace_filename = basename(input_trace_path)
    out_path = "{}/annotated_{}".format(args.out_dir, input_trace_filename)
    if input_trace_filename.startswith("mmio_"):
        gen_descr = gen_mmio_descr
    elif input_trace_filename.startswith("bbs_"):
        gen_descr = gen_bb_descr
    else:
        print("need bbs_, mmio_ trace...")
        exit(1)

    new_contents = ""
    for l in lines:
        if l == "":
            continue

        descr = gen_descr(l)

        new_line = "{}\t\t{}\n".format(l.rstrip(), descr)
        new_contents += new_line

    print("Writing out contents to {}".format(out_path))
    with open(out_path, "w") as out:
        out.write(new_contents)