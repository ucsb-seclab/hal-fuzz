from unicorn.arm_const import *
from ..globs import debug_enabled
RF233_REG_TRX_STATUS = 1
regs = {}


def trx_reg_read(uc):
    reg_id = uc.reg_read(UC_ARM_REG_R0)
    if reg_id in regs:
        res = regs[reg_id]
    else:
        res = 0
    
    if debug_enabled:
        print("trx_reg_read[{:d}] -> 0x{:x}".format(reg_id, res))

    uc.reg_write(UC_ARM_REG_R0, res)


def trx_reg_write(uc):
    reg_id = uc.reg_read(UC_ARM_REG_R0)
    val = uc.reg_read(UC_ARM_REG_R1)

    if debug_enabled:
        print("trx_reg_write[{:d}] = 0x{:x}".format(reg_id, val))

    regs[reg_id] = val
    # TODO: this seems to be expected to be the same as reg nr 2 after nr 2 is written to. Figure out what this is all about
    regs[RF233_REG_TRX_STATUS] = val

