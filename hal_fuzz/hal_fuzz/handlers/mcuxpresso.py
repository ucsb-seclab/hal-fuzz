import sys
import time
from ..models.ethernet import EthernetModel
from ..util import int2bytes
from unicorn.arm_const import *
from ..models.timer import Timer

from ..util import bytes2int


def UART_WriteBlocking(uc):
    # args: uart base, buff, len
    #uart_base = = uc.reg_read(UC_ARM_REG_R0)
    ptr = uc.reg_read(UC_ARM_REG_R1)
    len = uc.reg_read(UC_ARM_REG_R2)
    to_write = uc.mem_read(ptr, len)
    sys.stdout.write(to_write.decode('ascii'))


def UART_ReadBlocking(uc):
    # args: uart base, buff, len
    #uart_base = = uc.reg_read(UC_ARM_REG_R0)
    ptr = uc.reg_read(UC_ARM_REG_R1)
    len = uc.reg_read(UC_ARM_REG_R2)
    to_read = sys.stdin.read(len)
    uc.mem_write(ptr, to_read.encode('ascii'))

ready = False
def ENET_GetRxFrameSize(uc):
    global ready
    frame_len_ptr = uc.reg_read(UC_ARM_REG_R1)
    # args: handle, num_frames_ptr
    if not ready:
        ready = True
        uc.reg_write(UC_ARM_REG_R0, 4002)
        uc.mem_write(frame_len_ptr, int2bytes(0))
    else:
        ready = False
        num_frames, len_next_frame = EthernetModel.get_frame_info('ENET')
        print("Got frame of length %d" % len_next_frame)
        # Put the length into arg1

        uc.mem_write(frame_len_ptr, int2bytes(len_next_frame))
        # Return 4000 (the 'i have a frame' code
        uc.reg_write(UC_ARM_REG_R0, 4000)


def ENET_SendFrame(uc):
    # args: base, handle, data_ptr, len
    data_ptr = uc.reg_read(UC_ARM_REG_R2)
    len = uc.reg_read(UC_ARM_REG_R3)
    data = uc.mem_read(data_ptr, len)
    EthernetModel.tx_frame('ENET', data)


def ENET_ReadFrame(uc):
    # args: base, handle, data_ptr, len
    data_ptr = uc.reg_read(UC_ARM_REG_R2)
    len = uc.reg_read(UC_ARM_REG_R3)
    # Get the next frame
    data = EthernetModel.get_rx_frame('ENET')
    uc.mem_write(data_ptr, data)
    # return 0
    uc.reg_write(UC_ARM_REG_R0, 0)


def PHY_GetLinkStatus(uc):
    status_ptr = uc.reg_read(UC_ARM_REG_R2)
    # we are always connected
    uc.mem_write(status_ptr, b'\x01')
    # Return 0
    uc.reg_write(UC_ARM_REG_R0, 0)


def PHY_GetLinkSpeedDuplex(uc):
    speed_ptr = uc.reg_read(UC_ARM_REG_R2)
    duplex_ptr = uc.reg_read(UC_ARM_REG_R3)
    # we are full-speed
    uc.mem_write(speed_ptr, b'\x01')
    # we are full-duplex
    uc.mem_write(duplex_ptr, b'\x01')
    # Return 0
    uc.reg_write(UC_ARM_REG_R0, 0)


ticks_per_tock = 120
basic_blocks_per_tick = 10000


def sys_now(uc):
    uc.reg_write(UC_ARM_REG_R0, Timer.ticks()//basic_blocks_per_tick)
