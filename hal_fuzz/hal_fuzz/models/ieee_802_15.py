from ..nvic import NVIC
from ..exit import do_exit
from ..handlers.fuzz import get_fuzz, fuzz_remaining
from collections import deque
from binascii import hexlify
import sys


marker = b'\xbe\xef\xfa\xce'

class IEEE802_15_4(object):

    frame_queue = deque()
    calc_crc = True
    rx_frame_isr = None
    rx_isr_enabled = False

    @classmethod
    def enable_rx_isr(cls):
        cls.rx_isr_enabled = True

    @classmethod
    def disable_rx_isr(cls):
        cls.rx_isr_enabled = False

    @classmethod
    def tx_frame(cls, frame):
        print("Sending: {}".format(hexlify(frame)))

    @classmethod
    def get_fuzz_frames(cls):
        if fuzz_remaining() == 0:
            # we're done
            do_exit(0)
        while fuzz_remaining() > 0:
            frame = b""
            while fuzz_remaining() > 0 and not frame.endswith(marker):
                frame += get_fuzz(1)
            if frame.endswith(marker):
                frame = frame[:-len(marker)]
            if len(frame) > 255:
                # AFL fucked up
                do_exit(1)
            cls.frame_queue.append(frame)

    @classmethod
    def rx_frame(cls):
        if not cls.frame_queue:
            cls.get_fuzz_frames()

    @classmethod
    def has_frame(cls):
        return len(cls.frame_queue) > 0

    @classmethod
    def get_first_frame(cls):
        frame = None
        if len(cls.frame_queue) > 0:
            frame = cls.frame_queue.popleft()
        return frame

    @classmethod
    def get_frame_info(cls):
        queue = cls.frame_queue
        if queue:
            return len(queue), len(queue[0])
        return 0, 0

