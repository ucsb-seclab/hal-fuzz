from unicorn.arm_const import *
import signal
import os
from ...exit import do_exit

def return_zero(uc):
    uc.reg_write(UC_ARM_REG_R0, 0)

def crash(uc):
    print("[*] Crashing handler at 0x{:08x} triggered, crashing now".format(uc.reg_read(UC_ARM_REG_PC)))
    os.kill(os.getpid(), signal.SIGSEGV)

def exit(uc):
    print("[*] exit block hook invoked")
    do_exit(0)

def hello(uc):
    print("[*] hello from test handler")

def hal_assert(uc, msg, cond):
    if not cond:
        print("Assertion failed: {}".format(msg))
        crash(uc)