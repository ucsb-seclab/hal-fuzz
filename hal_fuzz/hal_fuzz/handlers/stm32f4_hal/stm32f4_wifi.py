from unicorn.arm_const import *

from .. import fuzz
from ...models.tcp import TCP
from ...models.timer import Timer

WIFI_OFF = 1
WIFI_IDLE = 2
WIFI_CONNECTED = 3
WIFI_STATE_NAMES = {
    1: "WIFI_OFF",
    2: "WIFI_IDLE",
    3: "WIFI_CONNECTED"
}

stm32_wifi_state = WIFI_OFF


def wifi_init(uc):
    '''
        Register the timers
    '''
    # TODO: make generic
    tim1 = 0x40000400
    wifi_timer_rate = 5000
    Timer.start_timer(hex(tim1), wifi_timer_rate, 45)
    uc.reg_write(UC_ARM_REG_R0, 0)


def wifi_socket_server_open(uc):
    '''
        Should call listen()
        Arg1: Port number
        Arg2: The protocol (an enum, only TCP is supported)

    '''
    port = uc.reg_read(UC_ARM_REG_R0)
    print("wifi_socket_server_open called, listening on port %d" % port)
    TCP.listen(port)
    uc.reg_write(UC_ARM_REG_R0, 0)


def wifi_socket_server_write(uc):
    '''
        This version only supports the TCP/IP layer, do nothing
    '''
    length = uc.reg_read(UC_ARM_REG_R0)
    data = uc.mem_read(uc.reg_read(UC_ARM_REG_R1), length)
    TCP.tx_packet(data)


RX_DATA_BUF = 0x200f0000


def wifi_tim_handler(uc):
    """
    The STM32 Wifi stack's event dispatch queue
    Should be called over and over by a timer

    :param uc:
    :return:
    """
    global stm32_wifi_state
    # print("wifi_tim_handler called, current state: {}".format(WIFI_STATE_NAMES[stm32_wifi_state]))
    if stm32_wifi_state == WIFI_OFF:
        # We just booted. Because we are not emulating 802.11, we just say that we're connected
        # The user app will call listen() for us, so just give it a nudge.
        # call `ind_wifi_connectedi`
        stm32_wifi_state = WIFI_IDLE
        print("Setting wifi_connected state")
        uc.reg_write(UC_ARM_REG_PC, uc.symbols['ind_wifi_connected'])
    # If a client has connected, and we don't know that yet, call the callback and set the mode.
    elif stm32_wifi_state == WIFI_IDLE and TCP.is_client_connected():
        print("Loading fuzz during wifi connection startup")
        for line in fuzz.get_fuzz(fuzz.fuzz_remaining()).split(b"\0"):
            TCP.enqueue_packet(bytes(line))

        # We're connected!
        # Call `ind_wifi_socket_server_client_joined`
        stm32_wifi_state = WIFI_CONNECTED

        print("Setting wifi_socket_server_client_joined state")
        uc.reg_write(
            UC_ARM_REG_PC, uc.symbols['ind_socket_server_client_joined'])
    elif stm32_wifi_state == WIFI_CONNECTED:
        # Try to get some data!
        data = TCP.get_rx_packet()
        if data is not None:
            # We got one!
            print("Wifi: Received %s" % repr(data))
            # FIXME: It would be nice if we had a better way to do this.  We don't, but that's fine.
            data += b'\0'
            uc.mem_write(RX_DATA_BUF, bytes(data))  # Null-terminate
            # Call `ind_wifi_socket_data_received`
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_R1, RX_DATA_BUF)
            uc.reg_write(UC_ARM_REG_R2, len(data))
            uc.reg_write(UC_ARM_REG_R3, len(data))
            uc.reg_write(
                UC_ARM_REG_PC, uc.symbols['ind_wifi_socket_data_received'])
        else:
            # The client left!
            # Call `ind_wifi_socket_server_client_left`
            print("Client left, setting wifi_socket_server_client_left state")
            stm32_wifi_state = WIFI_IDLE
            uc.reg_write(
                UC_ARM_REG_PC, uc.symbols['ind_socket_server_client_left'])
