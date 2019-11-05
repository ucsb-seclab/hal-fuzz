import sys
from unicorn.arm_const import *
from ...util import *
from ...models.timer import Timer
import sys
from collections import defaultdict
from enum import Enum
# The HardwareTimer interface

# This HAL does the configuration separately, so we keep track


class ArduinoTimerMode(Enum):
    TIMER_DISABLED = 0
    # Output Compare
    TIMER_OUTPUT_COMPARE = 1                   # == TIM_OCMODE_TIMING           no output, useful for only-interrupt
    TIMER_OUTPUT_COMPARE_ACTIVE = 2            # == TIM_OCMODE_ACTIVE           pin is set high when counter == channel compare
    TIMER_OUTPUT_COMPARE_INACTIVE = 3         # == TIM_OCMODE_INACTIVE         pin is set low when counter == channel compare
    TIMER_OUTPUT_COMPARE_TOGGLE = 4       # == TIM_OCMODE_TOGGLE           pin toggles when counter == channel compare
    TIMER_OUTPUT_COMPARE_PWM1 = 5         # == TIM_OCMODE_PWM1             pin high when counter < channel compare, low otherwise
    TIMER_OUTPUT_COMPARE_PWM2 = 6           # == TIM_OCMODE_PWM2             pin low when counter < channel compare, high otherwise
    TIMER_OUTPUT_COMPARE_FORCED_ACTIVE = 7     # == TIM_OCMODE_FORCED_ACTIVE    pin always high
    TIMER_OUTPUT_COMPARE_FORCED_INACTIVE = 8   # == TIM_OCMODE_FORCED_INACTIVE  pin always low

    #Input capture
    TIMER_INPUT_CAPTURE_RISING = 9             # == TIM_INPUTCHANNELPOLARITY_RISING
    TIMER_INPUT_CAPTURE_FALLING = 10            # == TIM_INPUTCHANNELPOLARITY_FALLING
    TIMER_INPUT_CAPTURE_BOTHEDGE = 11           # == TIM_INPUTCHANNELPOLARITY_BOTHEDGE

    # Used 2 channels for a single pin. One channel in TIM_INPUTCHANNELPOLARITY_RISING another channel in TIM_INPUTCHANNELPOLARITY_FALLING.
    # Channels must be used by pair: CH1 with CH2, or CH3 with CH4
    # This mode is very useful for Frequency and Dutycycle measurement
    TIMER_INPUT_FREQ_DUTY_MEASUREMENT = 12
    TIMER_NOT_USED = 0xFFFF  # This must be the last item of this enum

class ArduinoTimer:
    rate = 1
    func = None
    channel = None
    mode = ArduinoTimerMode.TIMER_DISABLED
    obj = None
    timer_base = None

# Prescale factor is a global for all channels
prescale_factor = 1000

arduino_timers = defaultdict(ArduinoTimer) # maps channel to Timer

arduino_ticker = 0 # Tick in micros


def millis(uc):
    global arduino_ticker
    arduino_ticker += Timer.ticks() * prescale_factor
    uc.reg_write(UC_ARM_REG_R0, arduino_ticker // 1000)
    # TODO: Hm, this might overflow.  Deal with that.


def micros(uc):
    global arduino_ticker
    arduino_ticker += Timer.ticks() * prescale_factor
    uc.reg_write(UC_ARM_REG_R0, arduino_ticker)


def _ZN13HardwareTimerC2EP11TIM_TypeDef(uc):
    # EDG says: as far as I know, we can no-op this.
    #global arduino_timers
    tim_obj = uc.reg_read(UC_ARM_REG_R0) # A C++ object.
    tim_num = uc.reg_read(UC_ARM_REG_R1) # Which HW timer to use.
    print("HardwareTimer: Initializing object at %#08x backed by timer at %#08x" % (tim_obj, tim_num))
    arduino_timers[tim_obj].timer_base = tim_num
    # Returning self, don't set anything

def _ZN13HardwareTimer7setModeEm12TimerModes_t7PinName(uc):
    # void setMode(int channel, timer_mode mode);
    global arduino_timers
    obj = uc.reg_read(UC_ARM_REG_R0)
    chan = uc.reg_read(UC_ARM_REG_R1)
    mode = uc.reg_read(UC_ARM_REG_R2)
    print("Setting HardwareTimer (%#08x) channel %d to mode %d" % (obj, chan, mode))
    # We only support one channel for now
    arduino_timers[obj].mode = ArduinoTimerMode.TIMER_OUTPUT_COMPARE


def _ZN13HardwareTimer17setPrescaleFactorEm(uc):
    # void setPrescaleFactor(uint32_t prescaler); // set prescaler register (which is factor value - 1)
    global prescale_factor
    pf = uc.reg_read(UC_ARM_REG_R1)
    print("Setting HardwareTimer prescale factor to %d" % pf)
    prescale_factor = pf


def _ZN13HardwareTimer15attachInterruptEPFvPS_E(uc):
    # void attachInterrupt(voidFuncPtr handler);
    global arduino_timers
    obj = uc.reg_read(UC_ARM_REG_R0)
    func = uc.reg_read(UC_ARM_REG_R1)
    arduino_timers[obj].func = func
    arduino_timers[obj].obj = obj
    print("Setting HardwareTimer(%#08x) callback to %#08x" % (obj, func))
    import ipdb; ipdb.set_trace()

def _ZN13HardwareTimer15getTimerClkFreqEv(uc):
    #     uint32_t getTimerClkFreq();  // return timer clock frequency in Hz.
    uc.reg_write(UC_ARM_REG_R0, 80000000) # TODO our clock is 80mhz? Ok.


def _ZN13HardwareTimer11setOverflowEm13TimerFormat_t(uc):
    # void setOverflow(uint32_t val, TimerFormat_t format = TICK_FORMAT); // set AutoReload register depending on format provided
    # TODO: Do we care?
    print("HardwareTimer Set Overflow")


def _ZN13HardwareTimer6resumeEv(uc):
    #     void resume(void); // Resume counter and all output channels
    global arduino_timers
    obj = uc.reg_read(UC_ARM_REG_R0)
    for ch, t in arduino_timers.items():
        if t.mode != ArduinoTimerMode.TIMER_DISABLED:
            def timer_callback(uc):
                global arduino_timers
                my_timer = ch
                my_cb = arduino_timers[my_timer].func
                my_obj = obj
                print("Time up for timer %d" % my_timer)
                uc.reg_write(UC_ARM_REG_R0, my_obj)
                uc.reg_write(UC_ARM_REG_PC, my_cb | 1)
            Timer.start_timer(ch, t.rate * prescale_factor, timer_callback)


def _ZN13HardwareTimer7refreshEv(uc):
    #     // Refresh() can only be called after a 1st call to resume() to be sure timer is initialised.
    #     // It is usefull while timer is running after some registers update
    #     void refresh(void); // Generate update event to force all registers (Autoreload, prescaler,
    # compare) to be taken into account
    print("HardwareTimer Refresh")

def _ZN13HardwareTimer14updateCallbackEP17TIM_HandleTypeDef(uc):
    pass