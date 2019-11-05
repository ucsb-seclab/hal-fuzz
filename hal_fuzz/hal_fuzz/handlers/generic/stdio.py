from unicorn.arm_const import *
from ..fuzz import get_fuzz
import sys

def puts(uc):
    ptr = uc.reg_read(UC_ARM_REG_R0)
    assert(ptr != 0)
    msg = uc.mem_read(ptr, 256)
    #ptr += 1
    #while msg[-1] != b"\0":
    #    msg += uc.mem_read(ptr, 1)
    #    ptr += 1
    if b'\0' in msg:
        msg = msg[:msg.find(b'\0')]
    print(msg)


def putchar(uc):
    c = uc.reg_read(UC_ARM_REG_R0)
    assert (c < 256)
    sys.stdout.write(chr(c))
    sys.stdout.flush()

def printf(uc):
    # for now just print out the fmt string
    ptr = uc.reg_read(UC_ARM_REG_R0)
    assert(ptr != 0)
    msg = uc.mem_read(ptr, 256)
    # ptr += 1
    # while msg[-1] != b"\0":
    #    msg += uc.mem_read(ptr, 1)
    #    ptr += 1
    if b'\0' in msg:
        msg = msg[:msg.find(b'\0')]
    sys.stdout.write(msg.decode('latin1'))
    sys.stdout.flush()


def readline(uc):
    ptr = uc.reg_read(UC_ARM_REG_R0)
    l = uc.reg_read(UC_ARM_REG_R1)
    assert(ptr != 0)
    data = b''
    while len(data) < l:
        data += get_fuzz(1)
        if data.endswith(b'\n'):
            break
    uc.mem_write(ptr, data)
    uc.reg_write(UC_ARM_REG_R0, 0)
    # echo
    sys.stdout.write(data.decode('latin1'))
    sys.stdout.flush()