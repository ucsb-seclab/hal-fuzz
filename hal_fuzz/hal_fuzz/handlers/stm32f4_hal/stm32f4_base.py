from ...models.timer import Timer
from unicorn.arm_const import *

def systick_config(uc):
    #rate = qemu.regs.r0
    # TODO: Figure out the systick rate.
    rate = 2000
    systick_irq = 15
    print("Setting SysTick rate to %#08x" % rate)
    Timer.start_timer('SysTick', rate, systick_irq)
    uc.reg_write(UC_ARM_REG_R0, 0)

