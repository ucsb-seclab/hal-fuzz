import struct
import sys

from unicorn.arm_const import *

from ... import nvic
from ...exit import do_exit
from ...models import timer
from ...globs import debug_enabled

def handle_timeup(uc):
    # Update MMIO timer value
    curr_time,  = struct.unpack("<I", uc.mem_read(0x40000C24, 4))
    uc.mem_write(0x40000C24, struct.pack("<I", (curr_time+10000)&0xffffffff ))
    if debug_enabled:
        print("### blink_led.handle_timeup called, setting time to {}".format(curr_time))
    # Pend interrupt manually
    nvic.NVIC.set_pending(62)

num_blinks = 0
def blink_led(uc):
    global num_blinks
    num_blinks += 1
    print("### Blinking LED for the {}. time ###".format(num_blinks))
    if num_blinks >= 10:
        print("### Maximum number of blinks reached, exiting ###")
        do_exit(0)

def register_timer(uc):
    global debug_enabled
    
    if debug_enabled:
        print("### blink_led.register_timer called")
    # num_us = uc.reg_read(UC_ARM_REG_R2)
    # First version: use direct python callback
    # timer.Timer.start_timer(0, 100, blink_led)
    
    # Second version: trigger an actual irq and override irq handler
    us_ticker_irq_handler = 0x0800200C
    timer.Timer.start_timer(0, 1000, 62)
    nvic.NVIC.write_irq_handler(62, us_ticker_irq_handler | 1)
    
def bad_stuff(uc):
    print("Encountered a path that we did not like...")
    exit(0)