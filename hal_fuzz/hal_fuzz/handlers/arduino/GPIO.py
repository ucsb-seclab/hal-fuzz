import sys
from unicorn.arm_const import *
from ...util import *
import sys
from collections import defaultdict

def pinMode(uc):
    # TODO: real stuff here when we do GPIO fuzzing!
    uc.reg_write(UC_ARM_REG_R0, 0)


pins = defaultdict(int)
pin_modes = defaultdict(int)


def digitalRead(uc):
    pin = uc.reg_read(UC_ARM_REG_R0)
    # digitalRead(pin)
    print("GPIO: Reading pin %d as %d" % (pin, pins[pin]))
    uc.reg_write(UC_ARM_REG_R0, pins[pin])


def pinMode(uc):
    pin = uc.reg_read(UC_ARM_REG_R0)
    mode = uc.reg_read(UC_ARM_REG_R1)
    print("GPIO: Setting pin %d to mode %d" % (pin, mode))
    pin_modes[pin] = mode


def digitalWrite(uc):
    # digitalWrite(pin, val)

    pin = uc.reg_read(UC_ARM_REG_R0)
    val = uc.reg_read(UC_ARM_REG_R1)
    print("GPIO: Setting pin %d to value %d" % (pin, val))
    pins[pin] = val
    uc.reg_write(UC_ARM_REG_R0, 0)


def _Z7pulseInmmm(uc):
    # pulseIn(pin, value, timeout)
    pin = uc.reg_read(UC_ARM_REG_R0)
    val = uc.reg_read(UC_ARM_REG_R1)
    timeout = uc.reg_read(UC_ARM_REG_R2)
    print("GPIO: Reading Pulse Input on pin %d, value %d, timeout %d" % (pin, val, timeout))
    # HACK: FIXME:
    uc.reg_write(UC_ARM_REG_R0, 420)