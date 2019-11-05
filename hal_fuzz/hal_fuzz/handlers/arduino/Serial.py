import sys
from unicorn.arm_const import *
from ...util import *
import sys
from ..fuzz import fuzz_remaining, get_fuzz
from ...models.serial import SerialModel


def _ZN14HardwareSerial5beginEmh(uc):
    # HardwareSerial::begin(sobj, baud, flags)
    # TODO: Multi-serial support
    #serial_obj = uc.reg_read(UC_ARM_REG_R0)
    #baud = uc.reg_read(UC_ARM_REG_R1)
    pass


def _ZN5Print7printlnEPKc(uc):
    obj = uc.reg_read(UC_ARM_REG_R0)
    str_ptr = uc.reg_read(UC_ARM_REG_R1)
    # Oh god....
    s = b''
    while True:
        b = uc.mem_read(str_ptr, 1)
        s += b
        str_ptr += 1
        if b == b'\0':
            break
    SerialModel.tx(None, s + b'\n')


def _ZN5Print5printEii(uc):
    obj = uc.reg_read(UC_ARM_REG_R0)
    str_ptr = uc.reg_read(UC_ARM_REG_R1)
    # Oh god....
    s = b''
    while True:
        b = uc.mem_read(str_ptr, 1)
        s += b
        str_ptr += 1
        if b == b'\0':
            break
    SerialModel.tx(None, s)


def _ZN14HardwareSerial9availableEv(uc):

    if SerialModel.packet_serial:
        uc.reg_write(UC_ARM_REG_R0, len(SerialModel.cur_serial_frame))
        print("Current packet %s (len %d)" % (repr(SerialModel.cur_serial_frame), len(SerialModel.cur_serial_frame)))
        if len(SerialModel.cur_serial_frame) == 0:
            SerialModel.queue_frame(None)

    else:
        uc.reg_write(UC_ARM_REG_R0, fuzz_remaining())

def _ZN14HardwareSerial4readEv(uc):
    stuff = SerialModel.rx(None, count=1)
    if len(stuff) == 0:
        uc.reg_write(UC_ARM_REG_R0, -1)
    else:
        uc.reg_write(UC_ARM_REG_R0, ord(stuff))
