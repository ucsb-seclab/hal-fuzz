import yaml
import sys
import angr

fname = sys.argv[1]
outname = sys.argv[2]

if len(sys.argv) != 2:
    print("Usage: dump_symbols.py <non-blob binary> <output yaml file>")
p = angr.Project(fname)
info = {}
info['architecture'] = p.arch.name
info['entry_point'] = p.entry
info['base_address'] = p.loader.min_addr
cfg = p.analyses.CFGFast(resolve_indirect_jumps=True, cross_references=True, force_complete_scan=False, detect_tail_calls=True)
syms = {p.kb.functions[f].addr:p.kb.functions[f].name for f in p.kb.functions if not p.kb.functions[f].name.startswith("sub_")}
info['symbols'] = syms
with open(outname, 'w') as f:
    yaml.dump(info, f)
