import argparse
import os
import signal
import collections
import archinfo
import sys
import yaml
import gc
from .models import configure_models
from . import globs
from . import nvic
from . import interrupt_triggers
from .tracing import trace_bbs, trace_mem, snapshot, trace_ids
from .exit import do_exit
from . import native
from . import handlers
from .sparkle import add_sparkles
from .util import bytes2int
from unicorn import *
from unicorn.arm_const import *
from .handlers import func_hook_handler, add_func_hook, add_block_hook, register_global_block_hook, register_func_handler_hook
from .handlers import fuzz
import struct

#########
# Debugging stuff

try:
    # If Capstone is installed then we'll dump disassembly, otherwise just dump the binary.
    from capstone import *
    cs = Cs(CS_ARCH_ARM, CS_MODE_MCLASS|CS_MODE_THUMB)
    def unicorn_debug_instruction(uc, address, size, user_data):
        mem = uc.mem_read(address, size)
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))
    def debug_step(self):
        curpc = self.reg_read(UC_ARM_REG_PC)
        result = self.emu_start(curpc | 1, 0, timeout=0, count=1)
        newpc = self.reg_read(UC_ARM_REG_PC)
        size = newpc - curpc
        mem = self.mem_read(curpc, size)
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(bytes(mem), size):
            print("    Instr: {:#016x}:\t{}\t{}".format(curpc, cs_mnemonic, cs_opstr))
except ImportError:

    def unicorn_debug_instruction(uc, address, size, user_data):
        print("    Instr: addr= 0x{0:016x} , size=0x{1:016x}".format(address, size))    


def unicorn_debug_block(uc, address, size, user_data):
    print("Basic Block: addr= 0x{0:016x} , size=0x{1:016x} (lr=0x{2:x})".format(address, size, uc.reg_read(UC_ARM_REG_LR)))
    """
    if address == 0xE62:
        a = uc.mem_read(uc.reg_read(UC_ARM_REG_SP)+0x1ec, 4).hex()
        b = uc.mem_read(uc.reg_read(UC_ARM_REG_SP) + 0x1e8, 4).hex()
        nxt = uc.mem_read(uc.reg_read(UC_ARM_REG_SP) + 0x1e4, 4).hex()
        code = uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 32*4).hex()
        junk = uc.mem_read(uc.reg_read(UC_ARM_REG_SP)+64*4, 32*4).hex()
        print("A: %s, B: %s, Next: %s" % (a, b, nxt))
        print("Code: %s", code)
        print("Junk: %s", junk)
        import ipdb; ipdb.set_trace()
    """

def unicorn_trace_syms(uc, address, size, user_data):
    if address in uc.syms_by_addr:
        print("Calling function: {}".format(uc.syms_by_addr[address]))
        #s = input(">")
        sys.stdout.flush()

def unicorn_debug_mem_access(uc, access, address, size, value, user_data):

    sp = uc.reg_read(UC_ARM_REG_SP)
    if (sp - 0x1000 < address < sp + 0x2000):
        if access == UC_MEM_WRITE:
            print("        >>> Write: addr= 0x{0:08x}[SP:{3:+04x}] size={1} data=0x{2:08x}".format(address, size, value, address - sp))
        else:
            value = uc.mem_read(address, size)
            print("        >>> Read: addr= 0x{0:08x}[SP:{3:+04x}] size={1} data=0x{2:s}".format(address, size, value.hex(), address - sp))
    else:
        if access == UC_MEM_WRITE:
            print("        >>> Write: addr= 0x{0:016x} size={1} data=0x{2:016x}".format(address, size, value))
        else:
            value = uc.mem_read(address, size)
            print("        >>> Read: addr= 0x{0:016x} size={1} data=0x{2:s}".format(address, size, value.hex()))
    sys.stdout.flush()


def unicorn_debug_mem_invalid_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE_UNMAPPED:
        print("        >>> INVALID Write: addr= 0x{0:016x} size={1} data=0x{2:016x}".format(address, size, value))
    else:
        print("        >>> INVALID Read: addr= 0x{0:016x} size={1}, pc= 0x{2:016x}".format(address, size, uc.reg_read(UC_ARM_REG_PC)))
    sys.stdout.flush()

###########
# This is the business end of our crappy crash detector
def force_crash(uc_error):
    # This function should be called to indicate to AFL that a crash occurred during emulation.
    # Pass in the exception received from Uc.emu_start()
    mem_errors = [
        UC_ERR_READ_UNMAPPED, UC_ERR_READ_PROT, UC_ERR_READ_UNALIGNED,
        UC_ERR_WRITE_UNMAPPED, UC_ERR_WRITE_PROT, UC_ERR_WRITE_UNALIGNED,
        UC_ERR_FETCH_UNMAPPED, UC_ERR_FETCH_PROT, UC_ERR_FETCH_UNALIGNED,
    ]
    from .exit import do_exit
    if uc_error.errno in mem_errors:
        # Memory error - throw SIGSEGV
        print("-------Memory Error Detected-------")
        sig = signal.SIGSEGV
    elif uc_error.errno == UC_ERR_INSN_INVALID:
        # Invalid instruction - throw SIGILL
        sig = signal.SIGILL
    else:
        # Not sure what happened - throw SIGABRT
        sig = signal.SIGABRT
    do_exit(-1, sig)


###########
# Stuff about configuration files

def _merge_dict(dct, merge_dct):
    for k, v in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            _merge_dict(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


def configure_unicorn(args):
    print("Loading configuration in %s" % args.config)
    with open(args.config, 'rb') as infile:
        config = yaml.load(infile, Loader=yaml.FullLoader)
    if 'include' in config:
        # Merge config files listed in 'include' in listed order
        # Root file gets priority
        newconfig = {}
        for f in config['include']:
            # Make configs relative to the including file
            if not f.startswith("/"):
                cur_dir = os.path.dirname(args.config)
                f = os.path.abspath(os.path.join(cur_dir, f))
            print("\tIncluding configuration from %s" % f)
            with open(f, 'rb') as infile:
                _merge_dict(newconfig, yaml.load(infile, Loader=yaml.FullLoader))
        _merge_dict(newconfig, config)
        config = newconfig

    # Step 2: Set up the memory map
    if 'memory_map' not in config:
        print("Memory Configuration must be in config file")
        quit(-1)

    # Create the unicorn
    # TODO: Parse the arch, using archinfo
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)

    regions = {}
    for rname, region in config['memory_map'].items():
        prot = 0
        if 'permissions' in region:
            prot = 7 # UC_PROT_ALL
        if 'r' in region['permissions']:
            prot |= 1
        if 'w' in region['permissions']:
            prot |= 2
        if 'x' in region['permissions']:
            prot |= 4
        print("Mapping region %s at %#08x, size %#08x, perms: %d" % (rname, region['base_addr'], region['size'], prot))
        regions[rname] = (region['base_addr'], region['size'], prot)
        uc.mem_map(region['base_addr'], region['size'], prot)
        if 'file' in region:
            file_offset = 0
            load_offset = 0
            file_size = region['size']
            if 'file_offset' in region:
                file_offset = region['file_offset']
            if 'load_offset' in region:
                load_offset = region['load_offset']
            if 'file_size' in region:
                file_size = region['file_size']
            if not region['file'].startswith("/"):
                cur_dir = os.path.dirname(args.config)
                f = os.path.join(cur_dir, region['file'])
            print("Using file %s, offset %#08x, load offset: %#08x, file_size: %#08x" % (f, file_offset, load_offset, file_size))
            with open(f, 'rb') as fp:
                fp.seek(file_offset)
                region_data = fp.read(file_size)
                print("Loading %#08x bytes at %#08x" % (len(region_data), region['base_addr'] + load_offset))
                uc.mem_write(region['base_addr'] + load_offset, region_data)
    globs.regions = regions

    # Native mmio fuzzing
    if not os.path.exists(args.native_lib):
        print("Native library %s does not exist!" % args.native_lib)
        exit(1)
    native.init(uc, args.native_lib, False, [], 0, None, [])

    name_to_addr = {}
    addr_to_name = {}

    # Create the symbol table
    if 'symbols' in config:
        addr_to_name = {k&0xFFFFFFFE: v for k, v in config['symbols'].items()}
        name_to_addr = {v: k for k, v in config['symbols'].items()}

    # Step 3: Set the handlers
    if 'handlers' in config and config['handlers']:
        for fname, handler_desc in config['handlers'].items():
            if 'addr' in handler_desc and isinstance(handler_desc['addr'], int):
                # This handler is always at a fixed address
                handler_desc['addr'] = handler_desc['addr'] & 0xFFFFFFFE  # Clear thumb bit
                addr_to_name[handler_desc['addr']] = fname
            else:
                # No static address specified, look in the symbol table
                if not name_to_addr:
                    print("Need symbol table in order to hook named functions!")
                    sys.exit(1)
                if fname not in name_to_addr:
                    # We can't hook this
                    print("No symbol found for %s" % fname)
                    continue
                handler_desc['addr'] = name_to_addr[fname]
            if not 'do_return' in handler_desc:
                handler_desc['do_return'] = True

            if 'handler' not in handler_desc:
                handler_desc['handler'] = None

            # Actually hook the thing
            print("Handling function %s at %#08x with %s" % (fname, handler_desc['addr'], handler_desc['handler']))
            add_func_hook(uc, handler_desc['addr'], handler_desc['handler'], do_return=handler_desc['do_return'])
            
    if 'opcodes' in config and config['opcodes']:
        for opcode, code in config['opcodes'].items():
            add_intr_hook(uc,code['name'])
            print("Handling opcode %s"%(code['name']))

    if args.ram_trace_file is not None:
        trace_mem.init_ram_tracing(uc, args.ram_trace_file, config)

    if args.bb_trace_file is not None:
        trace_bbs.register_handler(uc, args.bb_trace_file)

    if args.debug and args.trace_memory:
        add_block_hook(unicorn_debug_block)
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, unicorn_debug_mem_access)

    if args.debug and args.trace_funcs:
        add_block_hook(unicorn_trace_syms)

    # This is our super nasty crash detector
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID, unicorn_debug_mem_invalid_access)

    # Set the program entry point
    # TODO: Make this arch-independent
    if not 'entry_point' in config:
        print("Binary entry point missing! Make sure 'entry_point is in your configuration")
        sys.exit(1)
    # Set the initial stack pointer
    # TODO: make this arch-independent
    uc.reg_write(UC_ARM_REG_PC, config['entry_point'])
    uc.reg_write(UC_ARM_REG_SP, config['initial_sp'])


    # Implementation detail: Interrupt triggers need to be configured before the nvic (to enable multiple interrupt enabling)
    if 'interrupt_triggers' in config:
        interrupt_triggers.init_triggers(uc, config['interrupt_triggers'])

    use_nvic = ('use_nvic' in config and config['use_nvic'] is True)
    if use_nvic:
        vtor = globs.NVIC_VTOR_NONE
        num_vecs = globs.DEFAULT_NUM_NVIC_VECS
        if 'nvic' in config:
            num_vecs = config['nvic']['num_vecs'] if 'num_vecs' in config['nvic'] else globs.DEFAULT_NUM_NVIC_VECS

        native.init_nvic(uc, vtor, num_vecs, False)

    # Configure abstract peripheral models
    configure_models(uc, config)

    # At the end register the non-native accumulating block hook if any unconditional hooks have been registered
    if handlers.func_hooks:
        # In the native version we use a native check wrapper to avoid unconditional python block hooks
        native.register_cond_py_handler_hook(uc, handlers.func_hooks.keys())
    else:
        print("No function hooks found. Registering no native basic block hook for that")

    uc.symbols = name_to_addr
    uc.syms_by_addr = addr_to_name
    uc = add_sparkles(uc, args)
    register_global_block_hook(uc)
    return uc

def auto_int(x):
    return int(x, 0)

def main():
    parser = argparse.ArgumentParser(description="HALFuzz execution harness")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input to load")
    parser.add_argument('-s', '--single', default=False, action='store_true')
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Enables debug mode (required for -t and -M) (SLOW!)")
    parser.add_argument('-c', '--config')
    parser.add_argument('-M', '--trace-memory', default=False, action="store_true", dest='trace_memory',
                        help="Enables memory tracing")
    parser.add_argument('-t', '--trace-funcs', dest='trace_funcs', default=False, action='store_true')
    parser.add_argument('-l', '--instr-limit', dest='instr_limit', type=int, default=globs.DEFAULT_BASIC_BLOCK_LIMIT, help="Maximum number of instructions to execute. 0: no limit. Default: {:d}".format(globs.DEFAULT_BASIC_BLOCK_LIMIT))
    parser.add_argument('-n', '--use-native', dest='use_native', default=True, action='store_true')
    parser.add_argument("-b", '--breakpoint', dest='breakpoint', type=auto_int)
    parser.add_argument('--native-lib', dest='native_lib', default=os.path.dirname(os.path.realpath(__file__))+'/native/native_hooks.so', help="Specify the path of the native library")
    parser.add_argument('--mmio-trace-out', dest='mmio_trace_file', default=None)#, type=argparse.FileType("w"))
    parser.add_argument('--ram-trace-out', dest='ram_trace_file', default=None)#, type=argparse.FileType("w"))
    parser.add_argument('--bb-trace-out', dest='bb_trace_file', default=None)#, type=argparse.FileType("w"))


    args = parser.parse_args()
    globs.input_file_name = os.path.basename(args.input_file)

    if not args.use_native:
        print("Not using native mode is no longer supported")
        exit(-1)

    # In case tracing is requested but a basic block limit is not set, set a limit anyways
    if (args.bb_trace_file is not None or args.ram_trace_file is not None or args.mmio_trace_file is not None) and (args.instr_limit == 0 or args.instr_limit == globs.DEFAULT_BASIC_BLOCK_LIMIT):
        args.instr_limit = 1<<20

    globs.debug_enabled = args.debug

    uc = configure_unicorn(args)
    globs.uc = uc


    #-----------------------------------------------------
    # Emulate 1 instruction to kick off AFL's fork server
    #   THIS MUST BE DONE BEFORE LOADING USER DATA! 
    #   If this isn't done every single run, the AFL fork server 
    #   will not be started appropriately and you'll get erratic results!
    #   It doesn't matter what this returns with, it just has to execute at
    #   least one instruction in order to get the fork server started.
    
    # Execute 1 instruction just to startup the forkserver
    print("Starting the AFL forkserver by executing 1 instruction")

    # Collect garbage once in order to avoid doing so while fuzzing
    gc.collect()
    # gc.set_threshold(0, 0, 0)
    try:
        uc.emu_start(uc.reg_read(UC_ARM_REG_PC)|1, 0, 0, count=1)
    except UcError as e:
        print("ERROR: Failed to execute a single instruction (error: {})!".format(e))
        return

    #-----------------------------------------------
    # Load the mutated input and map it into memory
    native.load_fuzz(args.input_file)

    #------------------------------------------------------------
    # Emulate the code, allowing it to process the mutated input
    if args.single:
        while True:
            try:
                result = uc.emu_start(uc.reg_read(UC_ARM_REG_PC) | 1, 0, timeout=0, count=1)
            except UcError as e:
                print("Execution failed with error: {}".format(e))
                force_crash(e)
    print("Executing until a crash")
    try:
        result = uc.emu_start(uc.reg_read(UC_ARM_REG_PC)|1, 0, timeout=0, count=args.instr_limit)
    except UcError as e:
        print("Execution failed with error: {}".format(e))
        force_crash(e)

    print("Done.")
    do_exit(0)

if __name__ == "__main__":
    main()
