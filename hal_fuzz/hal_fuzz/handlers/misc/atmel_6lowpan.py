from unicorn.arm_const import *
from binascii import hexlify
from ..debug import print_context
from ...models.timer import Timer
import struct

def clock_init(uc):
    Timer.start_timer("tc", 5000, 0x88 // 4)
    uc.mem_write(0x88, struct.pack("<I", uc.symbols['etimer_request_poll']))