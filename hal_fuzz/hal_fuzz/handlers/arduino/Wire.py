import struct
from unicorn import UcError
from unicorn.arm_const import *
from ...util import crash
from ..fuzz import get_fuzz, fuzz_remaining
from ...models.i2c import I2CModel
from ...models.timer import Timer
from ...native import nvic_enter_exception
import sys

i2c_rx_callback = None
i2c_tx_callback = None



def i2c_t3_begin(uc):
    # _ZN6i2c_t35beginE8i2c_modeh8i2c_pins10i2c_pullupm11i2c_op_mode
    bus_mode = uc.reg_read(UC_ARM_REG_R1)
    op_mode = uc.mem_read(uc.reg_read(UC_ARM_REG_SP) + 0x8, 1)
    if bus_mode == 1:
        # slave
        if op_mode == b'\x01':
            # ISR mode
            print("Wire: Starting I2C bus in ISR Slave mode")

# For an i2c slave, implement speak-when-spoken-to
i2c_do_tx = False

def do_rx_callback(uc):
    global i2c_rx_callback
    global i2c_do_tx
    fake_irq = 69
    if not i2c_do_tx:
        #print("I2C: Doing RX event")
        # We are the slave, get a packet
        I2CModel.queue_frame("i2c_t3", 0)
        data_len = len(I2CModel.cur_i2c_frame)
        assert(i2c_rx_callback is not None)
        nvic_enter_exception(uc, fake_irq)
        uc.reg_write(UC_ARM_REG_PC, i2c_rx_callback)
        # Args
        uc.reg_write(UC_ARM_REG_R0,data_len)
        i2c_do_tx = True
    elif i2c_tx_callback is not None:
        # We did the thing with the packet, so respond.
        nvic_enter_exception(uc, fake_irq)
        uc.reg_write(UC_ARM_REG_PC, i2c_tx_callback)
        # Args
        i2c_do_tx = False


def i2c_t3_on_receive(uc):
    global i2c_rx_callback
    i2c_rx_callback = uc.reg_read(UC_ARM_REG_R1)
    Timer.start_timer("i2c_data", 20000, do_rx_callback)

def i2c_t3_on_request(uc):
    global i2c_tx_callback
    i2c_tx_callback = uc.reg_read(UC_ARM_REG_R1)


def i2c_t3_write(uc):
    b = uc.reg_read(UC_ARM_REG_R1)
    #print("I2C: %s" % chr(b))


def i2c_t3_write_buf(uc):
    st = uc.reg_read(UC_ARM_REG_R1)
    len = uc.reg_read(UC_ARM_REG_R2)
    data = uc.mem_read(st, len)
    print("I2C: %s" % repr(data))
    sys.stdout.flush()

def i2c_t3_read_buf(uc):
    st = uc.reg_read(UC_ARM_REG_R1) # The string goes here
    l = uc.reg_read(UC_ARM_REG_R2) # length of the buffer
    assert(st != 0)
    data = I2CModel.rx('i2c_t3', 0, l)
    uc.mem_write(st, data)
    #print("I2C in: %s" % repr(data))
