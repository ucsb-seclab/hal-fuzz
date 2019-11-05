import time
from unicorn.arm_const import *


def nothing(uc):
    # Do nothing
    pass


generic_ticker_delta_ms = 0
generic_rtc_time = 0
generic_rtc_boot_time = 0


def get_ms(uc):
    """
    Handler that will return the delta since the current system start time in ms.
    :return:
    """

    global generic_ticker_delta_ms
    global generic_rtc_boot_time
    global generic_rtc_time

    if generic_rtc_boot_time == 0:
        generic_rtc_boot_time = int(round(time.time() * 1000))
        generic_rtc_time = generic_rtc_boot_time
        generic_ticker_delta_ms = 1
        uc.reg_write(UC_ARM_REG_R0, generic_ticker_delta_ms)
    else:
        generic_rtc_time = int(round(time.time() * 1000))
        generic_ticker_delta_ms = generic_rtc_time - generic_rtc_boot_time
        # TODO: Wrap it before.... it wraps you!
        uc.reg_write(UC_ARM_REG_R0, generic_rtc_boot_time)
