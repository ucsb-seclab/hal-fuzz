import sys
from unicorn.arm_const import *
from ..models.ethernet import EthernetModel
from ..util import *
import sys


########################### USART ###############################


def usart_write_wait(uc):
    #usart_ptr = uc.reg_read(UC_ARM_REG_R0)
    #hw_addr = bytes2int(uc.mem_read(usart_ptr, 4))
    data = int2bytes(uc.reg_read(UC_ARM_REG_R1))[:1] # Just the first byte
    sys.stdout.write(data.decode())
    uc.reg_write(UC_ARM_REG_R0, 0)


def usart_write_buffer_wait(uc):
    #usart_ptr = uc.reg_read(UC_ARM_REG_R0)
    #hw_addr = bytes2int(uc.mem_read(usart_ptr, 4))
    import ipdb; ipdb.set_trace()
    buf_addr = uc.reg_read(UC_ARM_REG_R1)
    buf_len = uc.reg_read(UC_ARM_REG_R2)
    data = uc.mem_read(buf_addr, buf_len)
    #sys.stdout.write(data)
    print(data)
    uc.reg_write(UC_ARM_REG_R0, 0)

########################### Ethernet ###############################


# netif Offsets
NETIF_STATE = 32
NETIF_INPUT = 16

# struct ksz8851snl_device Offsets
NUM_RX_BUFFS = 2
NUM_TX_BUFFS = 2

DEVICE_RX_DESC = 0
DEVICE_TX_DESC = 4 * NUM_RX_BUFFS
DEVICE_RX_PBUF = DEVICE_TX_DESC + (4 * NUM_TX_BUFFS)
DEVICE_TX_PBUF = DEVICE_RX_PBUF + (4 * NUM_RX_BUFFS)
DEVICE_RX_HEAD = DEVICE_TX_PBUF + (4 * NUM_TX_BUFFS)
DEVICE_RX_TAIL = DEVICE_RX_HEAD + 4
DEVICE_TX_HEAD = DEVICE_RX_TAIL + 4
DEVICE_TX_TAIL = DEVICE_TX_HEAD + 4
DEVICE_NETIF = DEVICE_TX_TAIL + 4

# pbuf offsets
PBUF_NEXT = 0
PBUF_PAYLOAD = 4
PBUF_TOT_LEN = 8
PBUF_LEN = 10
PBUF_TYPE = 12
PBUF_FLAGS = 13
PBUF_REF = 14

# Ethernet Types
ETHTYPE_ARP = 0x0806
ETHTYPE_IP = 0x0800

PADDING = 2  # Padding used on ethernet frames to keep alignment

SUPPORTED_TYPES = (ETHTYPE_ARP, ETHTYPE_IP)


ethernet_dev_ptr = None
ethernet_orig_lr = None
ethernet_netif_ptr = None

def is_supported_frame_type(frame):
    if len(frame) < 14:
        return False
    else:
        ty = struct.unpack('!H', frame[12:14])[0]
        #log.info("Frame ty: %s" % hex(ty))
        #log.info("Frame : %s" % binascii.hexlify(frame[:20]))
        return ty in (SUPPORTED_TYPES)



def get_id(uc):
    return 'ksz8851'


def call_populate_queues(uc):
    '''
    This will call the ksz8851snl_rx_populate_queue
    returning to ethernetif_input
    '''
    global ethernet_dev_ptr
    global ethernet_orig_lr
    ethernet_orig_lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_R0, ethernet_dev_ptr)
    uc.reg_write(UC_ARM_REG_LR, uc.reg_read(UC_ARM_REG_PC) | 1)  # Make sure thumb bit is set
    uc.reg_write(UC_ARM_REG_PC, uc.symbols['ksz8851snl_rx_populate_queue'] | 1)


def ethernetif_input(uc):
    # 1. See if there are frames
    #now = time.time()
    #log.info("In ETHERNET_INPUT: %f" % (now - self.last_exec_time))
    #self.last_exec_time = time.time()
    #start_time = time.time()
    global ethernet_orig_lr
    global ethernet_dev_ptr
    global ethernet_netif_ptr
    (num_frames, size_1st_frame) = EthernetModel.get_frame_info(get_id(uc))
    if num_frames > 0:
        if ethernet_netif_ptr is None:
            # Will be none if not returning from populate_queues
            ethernet_netif_ptr = uc.reg_read(UC_ARM_REG_R0)
            ethernet_dev_ptr = bytes2int(uc.mem_read(ethernet_netif_ptr + NETIF_STATE, 4))
        else:  # Executing on return from popluate_queues
            uc.reg_write(UC_ARM_REG_LR, ethernet_orig_lr)

        # Get Pbuf, if null use populate_queues to allocate new ones
        rx_pbuf_ptr = bytes2int(uc.mem_read(ethernet_dev_ptr + DEVICE_RX_PBUF, 4))
        if rx_pbuf_ptr == 0:
            call_populate_queues(uc)
            return

        frame = EthernetModel.get_rx_frame(get_id(uc))
        if frame != None and is_supported_frame_type(frame):
            # Remove pbuf addr from hw buffers. Allows new one to be made
            # and this one to be freed by stack
            uc.mem_write(ethernet_dev_ptr + DEVICE_RX_PBUF, int2bytes(0))

            # Get payload_ptr
            payload_ptr = bytes2int(uc.mem_read(rx_pbuf_ptr + PBUF_PAYLOAD, 4))

            # Write to memory
            uc.mem_write(payload_ptr + PADDING, frame)
            uc.mem_write(rx_pbuf_ptr + PBUF_TOT_LEN, int2bytes(len(frame))[:2])
            uc.mem_write(rx_pbuf_ptr + PBUF_LEN, int2bytes(len(frame))[:2])


            # Get input function, and call it
            input_fn_ptr = bytes2int(uc.mem_read(ethernet_netif_ptr + NETIF_INPUT, 4))
            # Call netif->input
            uc.reg_write(UC_ARM_REG_R0, rx_pbuf_ptr)
            uc.reg_write(UC_ARM_REG_R1, ethernet_netif_ptr)
            uc.reg_write(UC_ARM_REG_PC, input_fn_ptr)
            ethernet_dev_ptr = None
            ethernet_netif_ptr = None

def _do_exti(chan):
    # Set the EXTI, so that the CPU knows that we want a packet, not a button press or something
    # TODO: This is ugly.  Can we do better? EDG doesn't think so, but... someone should try
    sr = 1 << (chan & 0x1f)
    uc.mem_write(0x40001810, int2bytes(sr))
    # Pend interrupt manually
    nvic.NVIC.set_pending(20)  # That's EIC


def ksz8851snl_low_level_output(uc):
    #pbuf_free = uc.symbols['pbuf_free']
    pbuf_ptr = uc.reg_read(UC_ARM_REG_R1)
    frame_bufs = []
    p = pbuf_ptr
    # os.system('stty sane') # Make so display works
    # IPython.embed()
    padding = PADDING
    while p != 0:
        length = bytes2int(uc.mem_read(p + PBUF_LEN, 2) + b'\x00\x00')
        payload_ptr = bytes2int(uc.mem_read(p + PBUF_PAYLOAD, 4))
        frame_bufs.append(uc.mem_read(payload_ptr + padding, length - padding))
        padding = 0  # Padding only on first pbuf
        p = bytes2int(uc.mem_read(p + PBUF_NEXT, 4))

    frame = bytearray(b'').join(frame_bufs)
    EthernetModel.tx_frame(get_id(uc), frame)
    # qemu.call_ret_0(pbuf_free, pbuf_ptr)
