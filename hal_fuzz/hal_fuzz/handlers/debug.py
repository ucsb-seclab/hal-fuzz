from unicorn.arm_const import *

def stop(uc):
    print_context(uc)
    input("...")

def print_context(uc):
    print("==== State ====")
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    r2 = uc.reg_read(UC_ARM_REG_R2)
    r3 = uc.reg_read(UC_ARM_REG_R3)
    r4 = uc.reg_read(UC_ARM_REG_R4)
    r5 = uc.reg_read(UC_ARM_REG_R5)
    r7 = uc.reg_read(UC_ARM_REG_R7)
    sp = uc.reg_read(UC_ARM_REG_SP)
    pc = uc.reg_read(UC_ARM_REG_PC)
    print("r0: 0x{:x}\nr1: 0x{:x}\nr2: 0x{:x}\nr3: 0x{:x}\nr4: 0x{:x}\nr5: 0x{:x}\nr7: 0x{:x}\npc: 0x{:x}\nsp: 0x{:x}".format(r0, r1, r2, r3, r4, r5, r7, pc, sp))


def breakpoint(uc):
    import ipdb; ipdb.set_trace()
