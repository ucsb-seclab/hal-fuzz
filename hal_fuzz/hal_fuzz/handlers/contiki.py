from unicorn.arm_const import *
from ..models.timer import Timer
ticks_per_tock = 120
basic_blocks_per_tick = 10000

def clock_time(uc):
    uc.reg_write(UC_ARM_REG_R0, Timer.ticks//basic_blocks_per_tick)


def clock_seconds(uc):
    uc.reg_write(UC_ARM_REG_R0, (Timer.ticks // basic_blocks_per_tick) // ticks_per_tock)

def uip_chksum_fake(uc):
    uc.reg_write(UC_ARM_REG_R0, 0xffff)
