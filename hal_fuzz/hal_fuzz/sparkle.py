import unicorn
import archinfo
import types
from .handlers import add_block_hook
import struct
from collections import defaultdict

# SparklyUnicorn: A syntactic wrapper for working with Unicorn's objects that does not make my head hurt


class SparklyRegs(object):

    _uc = None

    def __init__(self, uc):
        self._uc = uc

    def __getattribute__(self, regname):
        myuc = object.__getattribute__(self, '_uc')
        for x in dir(unicorn.arm_const):
            if x.endswith('_' + regname.upper()):
                return myuc.reg_read(getattr(unicorn.arm_const, x))
        return object.__getattribute__(self, regname)

    def get_all(self):
        out = {}
        myuc = object.__getattribute__(self, '_uc')
        for reg in myuc.arch.register_list:
            if not reg.artificial:
                n = reg.name
                try:
                    val = getattr(self, reg.name)
                    out[n] = val
                except AttributeError:
                    pass
        return out


    def __setattr__(self, regname, val):
        if regname == "_uc":
            object.__setattr__(self, regname, val)
        myuc = object.__getattribute__(self, '_uc')
        for x in dir(unicorn.arm_const):
            if x.endswith('_' + regname.upper()):
                return myuc.reg_write(getattr(unicorn.arm_const, x), val)
        return object.__getattribute__(self, regname)

    def __repr__(self):
        myuc = object.__getattribute__(self, '_uc')

        s = "Unicorn Registers:\n----------------\n"
        for reg in myuc.arch.register_list:
            if not reg.artificial:
                n = reg.name
                try:
                    val = getattr(self, reg.name)
                    s += "%s: %#08x\n" % (n, val)
                except AttributeError:
                    pass
        return s


class SparklyMem(object):

    _uc = None

    def __init__(self, uc):
        self._uc = uc

    def __getitem__(self, key):
        myuc = object.__getattribute__(self, '_uc')
        if isinstance(key, slice):
            return myuc.mem_read(key.start, (key.stop-key.start))
            # todo, striding support
        else:
            return myuc.mem_read(key, 4)
            # TODO: Word size via archinfo

    def __setitem__(self, key, value):
        if isinstance(value, bytes):
            myuc.mem_write(key, value)
        else:
            raise ValueError("Must be a bytes object")


class SparklyStack(object):

    _uc = None

    def __init__(self, uc):
        self._uc = uc

    def __getitem__(self, key):
        myuc = object.__getattribute__(self, '_uc')
        sp = myuc.reg_read(unicorn.arm_const.UC_ARM_REG_SP)
        if isinstance(key, slice):
            return myuc.mem_read(sp + key.start, (key.stop-key.start))
            # todo, striding support
        else:
            return myuc.mem_read(sp + key, 4)
            # TODO: Word size via archinfo

    def __setitem__(self, key, value):
        myuc = object.__getattribute__(self, '_uc')
        if isinstance(value, bytes):
            myuc.mem_write(sp + key, value)
        else:
            raise ValueError("Must be a bytes object")

    def _pp(self, start=-0x10, end=0x10, downward=True):
        if start % 4 != 0 or end % 4 != 0:
            print("WARNING: Dude, the stack on ARM is word-aligned! Did you skip ARM day?")
            start -= start % 4
            end -= end % 4
        myuc = object.__getattribute__(self, '_uc')
        data = self[start:end]
        sp = myuc.regs.sp
        start_addr = sp+start
        end_addr = sp+end
        regs = myuc.regs.get_all()

        points_to = defaultdict(list)
        for reg, val in regs.items():
            points_to[val - (val % 4)].append(reg)
        out = []
        for word in range(0, len(data), 4):
            bs = struct.unpack(">I", data[word:word+4])[0]
            line = "%#08x(SP%+#02x): %#010x" % (start_addr+word, (start_addr+word)-sp, bs)
            if points_to[start_addr+word]:
                line += "<-" + ",".join(points_to[start_addr+word])
            out.append(line)
        if downward is True:
            out = list(reversed(out))
        return "\n".join(out)

    def pp(self, start, end, downward=False):
        print(self._pp(start, end, downward))

def step(self, fancy=False):
    curpc = self.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
    result = self.emu_start(curpc | 1, 0, timeout=0, count=1)
    newpc = self.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
    size = newpc - curpc
    if fancy:
        cs = self.arch.capstone
        mem = self.mem_read(curpc, 4) # TODO: FIXME
        insns = list(cs.disasm_lite(bytes(mem), size))
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in insns[:1]:
            print("    Instr: {:#08x}:\t{}\t{}".format(curpc, cs_mnemonic, cs_opstr))

def break_it(uc):
    print(repr(uc.stack))
    print(repr(uc.regs))
    import ipdb; ipdb.set_trace()

def add_breakpoint(addr):
    global breakpoints
    breakpoints.append(addr)
    return breakpoints.index(addr)


def del_breakpoint(handle):
    global breakpoints
    if handle in breakpoints:
        breakpoints[breakpoitns.index(handle)] = -1
    else:
        breakpoints[handle] = -1


breakpoints = []
def breakpoint_handler(uc, address, size, user_data):
    global breakpoints
    if address in breakpoints:
        print("[*] Breakpoint hit at %#089x" % address)
        break_it(uc)


def add_sparkles(uc, args):
    global breakpoints
    uc.regs = SparklyRegs(uc)
    uc.mem = SparklyMem(uc)
    uc.stack = SparklyStack(uc)
    uc.step = types.MethodType(step, uc)
    if args.debug and args.breakpoint:
        add_block_hook(breakpoint_handler)
        breakpoints.append(args.breakpoint)
    uc.arch = archinfo.ArchARMCortexM()
    return uc
