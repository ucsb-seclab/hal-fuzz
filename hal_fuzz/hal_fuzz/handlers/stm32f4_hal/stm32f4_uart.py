import struct
from unicorn import UcError
from unicorn.arm_const import *
from ...util import crash
from ..fuzz import get_fuzz
from ...models.serial import SerialModel
from ...models.timer import Timer


def HAL_UART_Transmit(uc):
    UartMsgHandle = uc.reg_read(UC_ARM_REG_R0)
    (Instance, Init, pTxBuffPtr, TxXferSize, txXferCount, pRxBuffPtr, RxXferSize, RxXferCount, hdmatx, hdmarx, Lock, gState, RxState, ErrorCode) = struct.unpack("<IIHHIHHIIBBBBI", uc.mem_read(UartMsgHandle, 36))
    if Instance == 0:
        print("Policy violation: UartMsgHandle->Instance is a nullpointer")
        crash()
    else:
        try:
            uc.mem_read(Instance, 1)
        except UcError:
            print("Policy violation: UartMsgHandle->Instance does not point to mapped region")
            crash()


def HAL_UART_Receive_IT(uc):
    UartMsgHandle = uc.reg_read(UC_ARM_REG_R0)
    buf = uc.reg_read(UC_ARM_REG_R1)
    len = uc.reg_read(UC_ARM_REG_R2)
    assert(buf != 0)
    out = get_fuzz(len)
    uc.mem_write(buf, out)
    uc.reg_write(UC_ARM_REG_R0, 0)
    # This schedules the arrival of transaction complete events.  These are needed to
    # make sure recursive calls to this function don't cause infinite interrupts
    if SerialModel.irq:
        if Timer.timer_exists('STM32_UART'):
            pass
            Timer.resume_timer('STM32_UART')
        else:
            Timer.start_timer("STM32_UART", 2500, SerialModel.irq)

def HAL_UART_IRQHandler(uc):
    Timer.stop_timer("STM32_UART")
    uc.reg_write(
        UC_ARM_REG_PC, uc.symbols['HAL_UART_RxCpltCallback'])