from binascii import hexlify
import os
import signal
from unicorn.arm_const import *

def write(uc):
    print("--------------------------------- Write happened -------------------------------------")
    UartMsgHandle = 0x20003790
    handle_struct = uc.mem_read(UartMsgHandle, 0x40)
    print("handle struct contents: {}".format(hexlify(handle_struct)))

def WiFi_Decode(uc):
    pl = uc.mem_read(uc.reg_read(UC_ARM_REG_R0), 0x200)
    print("########################################################### WiFi_Decode called!")
    print("Payload: {}".format(pl[:pl.index(b"\x00")]))

def WiFi_Decode_mset(uc):
    index = ord(uc.mem_read(0x200009AA, 1))
    print("-------------------------------- WiFi_Decode_mset with index {:d} encountered ----------------------------------".format(index))
