from ..models.ieee_802_15 import IEEE802_15_4
from ..models.timer import Timer
from ..nvic import NVIC
from ..util import int2bytes, bytes2int
from collections import defaultdict
from unicorn.arm_const import *
from binascii import hexlify
import struct

# IEEE-whatever standard "regs"
rf233_regs = defaultdict(int)

RF233_REG_IRQ_STATUS = 0x0F
RF233_REG_TRX_STATE = 0x02
RF233_REG_TRX_STATUS = 0x01
IRQ_TRX_END = 1 << 3

def SetIEEEAddr(uc):
    # void SetIEEEAddr(uint8_t *ieee_addr);
    addr = uc.reg_read(UC_ARM_REG_R0)
    IEEE802_15_4.IEEEAddr = uc.mem_read(addr, 8)
    print("SetIEEEAddr")
    # Returns void

def rf233_send(uc):
    r0 = uc.reg_read(UC_ARM_REG_R0)
    r1 = uc.reg_read(UC_ARM_REG_R1)
    frame = uc.mem_read(r0, r1 & 0xFF)
    IEEE802_15_4.tx_frame(frame)
    uc.reg_write(UC_ARM_REG_R0, 0)


def trx_frame_read(uc):
    buf = uc.reg_read(UC_ARM_REG_R0)
    size = uc.reg_read(UC_ARM_REG_R1)
    assert(size == 1) # we only support the usage to read the frame buffer to get the size of the current packet in SRAM
    if IEEE802_15_4.has_frame() is not None:
        num_frames, frame_len = IEEE802_15_4.get_frame_info()

        print("Reporting current frame len: %i" % (frame_len))
        uc.mem_write(buf, int2bytes(frame_len + 2)[:1])  #TODO: Only one byte? really?
    else:
        uc.mem_write(buf, '\x00')
    # Returns void


def trx_sram_read(uc):
    if IEEE802_15_4.has_frame() is not None:
        frame = IEEE802_15_4.get_first_frame()
        buf_addr = uc.reg_read(UC_ARM_REG_R1)
        buf_size = uc.reg_read(UC_ARM_REG_R2)
        print("trx_sram_read. Writing {} bytes to 0x{:x}: {}".format(len(frame), buf_addr, hexlify(frame)))

        if len(frame) <= buf_size:
            uc.mem_write(buf_addr, frame)
    # Returns void


def rf233_on(uc):
    # Schedule the eventual arrival of packets!
    print("RF233: ON")
    IEEE802_15_4.enable_rx_isr()
    Timer.start_timer("rf233_packets", 2500, receive_packet)
    uc.reg_write(UC_ARM_REG_R0, 0)

def _do_exti(uc, chan):
    # Set the EXTI, so that the CPU knows that we want a packet, not a button press or something
    # TODO: This is ugly.  Can we do better? EDG doesn't think so, but... someone should try
    sr = 1 << (chan & 0x1f)
    uc.mem_write(0x40001810, int2bytes(sr))
    # Pend interrupt manually
    NVIC.set_pending(20)  # That's EIC

def receive_packet(uc):
    # A packet arrives when this function is called.
    # For the purpose of fuzzing, we do this on a "timer-less timer"
    # TODO: Something cooler than that
    IEEE802_15_4.rx_frame()
    _do_exti(uc, 0)

def rf233_off(uc):
    print("RF233: OFF")
    IEEE802_15_4.disable_rx_isr()
    Timer.stop_timer("rf233_packets")
    uc.reg_write(UC_ARM_REG_R0, 0)


def trx_reg_read(uc):
    global rf233_regs
    reg = uc.reg_read(UC_ARM_REG_R0)
    if reg == RF233_REG_IRQ_STATUS:
        ret_val = 0
        if IEEE802_15_4.has_frame():
            ret_val = IRQ_TRX_END
    elif reg == RF233_REG_TRX_STATUS:
        ret_val = rf233_regs[RF233_REG_TRX_STATE]
    elif reg in rf233_regs:
        ret_val = rf233_regs[reg]
    else:
        print("trx_reg_read: %s Unimplemented register returning  0" % reg)
        ret_val = 0
    uc.reg_write(UC_ARM_REG_R0, ret_val)


def trx_reg_write(uc):
    global rf233_regs
    reg = uc.reg_read(UC_ARM_REG_R0)
    val = uc.reg_read(UC_ARM_REG_R1)
    rf233_regs[reg] = val
    # Returns void


rf233_eui64 = b""
def get_edbg_eui64(uc):
    global rf233_eui64
    packet = uc.reg_read(UC_ARM_REG_R1)
    packet_struct = uc.mem_read(packet+2, 6)
    (length, data_ptr) = struct.unpack("<HI", packet_struct)
    if length > len(rf233_eui64):
        eui64 = rf233_eui64 + b"\55" * (length - len(rf233_eui64))
        uc.mem_write(data_ptr, eui64)
    else:
        uc.mem_write(data_ptr, eui64)
    uc.reg_write(UC_ARM_REG_R0, 0)
