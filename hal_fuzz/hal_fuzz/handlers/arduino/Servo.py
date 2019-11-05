import sys
from unicorn.arm_const import *
from ...util import *
from ...models.timer import Timer
import sys


# EDG: That's right folks, this fuzzer has... virtual servos! Isn't HLE great?

servos = {} # Keep track of our servos, by their objects.  Arduino servos are usually (as in, always) globals in the BSS

class Servo:
    pos = 700  # by the docs, most servos start here!
    min = 544 # These are the default min/max from the code
    max = 2400
    pin = None


def _ZN5ServoC2Ev(uc):
    # Constructor
    obj = uc.reg_read(UC_ARM_REG_R0)
    print("Servo: Creating new servo at %#08x" % (obj))
    servos[obj] = Servo()


def _ZN5Servo6attachEi(uc):
    global servos
    obj = uc.reg_read(UC_ARM_REG_R0)
    pin = uc.reg_read(UC_ARM_REG_R1)
    print("Servo: Attaching servo %#08x to pin %d" % (obj, pin))
    servos[obj].pin = pin


def _ZN5Servo5writeEi(uc):
    global servos
    obj = uc.reg_read(UC_ARM_REG_R0)
    val = uc.reg_read(UC_ARM_REG_R1)
    if obj not in servos:
        print("OUCH: Servo %#08x does not exist!" % obj)
        crash(11)
    s = servos[obj]
    if 0 <= val <= 360:
        # This is an angle.  Worst. Design. Ever.
        val = s.min + ((val / 360) * (s.max - s.min))
    print("Servo: Writing pulse of %d to servo %#08x" % (val, obj))
    if not (s.min <= val <= s.max):
        print("OUCH: You broke your servo.  Nice job buddy.")
        crash(11)
    servos[obj].pos = val
