import sys
import time
from .fuzz import fuzz_remaining
from unicorn.arm_const import *

from ..util import bytes2int


def serial_getc(uc):
    c = sys.stdin.read(1)
    print(">>> %s" % c)
    uc.reg_write(UC_ARM_REG_R0, ord(c))


def serial_putc(uc):
    c = chr(uc.reg_read(UC_ARM_REG_R1))
    print("<<< %s" % c)
    sys.stdout.write(c)


def serial_puts(uc):
    ptr = uc.reg_read(UC_ARM_REG_R1)
    while True:
        c = uc.mem_read(ptr, 1)[0]
        if c == 0:
            break
        print("<<< %s" % c)
        sys.stdout.write(chr(c))
        ptr += 1


def serial_writable(uc):
    uc.reg_write(UC_ARM_REG_R1, 1)


def serial_readable(uc):
    if fuzz_remaining() > 0:
        uc.reg_write(UC_ARM_REG_R0, 1)
    else:
        uc.reg_write(UC_ARM_REG_R0, 0)

# Deterministic RTC
last_time = None

def mbed_time(uc):
    global last_time
    if not last_time:
        last_time = 12345678
    else:
        last_time += 1000

    uc.reg_write(UC_ARM_REG_R0, last_time)

def mbed_time_set(uc):
    global last_time
    the_time = uc.reg_read(UC_ARM_REG_R0)
    last_time = the_time

def hal_rtc_getdate(uc):
    lol = b'\x01\x01\x01\x18'
    ptr = uc.reg_read(UC_ARM_REG_R1)
    uc.mem_write(ptr, lol)

def hal_rtc_gettime(uc):
    ptr = uc.reg_read(UC_ARM_REG_R1)
    lol = b'\x00' * 20 # size of struct is 20
    uc.mem_write(ptr, lol)
