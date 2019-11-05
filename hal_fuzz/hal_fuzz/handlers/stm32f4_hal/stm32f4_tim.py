from ...models.timer import Timer
from unicorn.arm_const import *
from ...util import bytes2int, int2bytes
from ...globs import debug_enabled

# TODO: FIXME: This should be abstracted out into a yaml or something
addr2isr_lut = {
            #'0x40000200': 0x32
            0x40000400: 45
        }


def tim_base_start_it(uc):
    tim_obj = uc.reg_read(UC_ARM_REG_R0)
    tim_base = bytes2int(uc.mem_read(tim_obj, 4))

    print("STM32_TIM start, base: %#08x" % tim_base)
    Timer.start_timer(hex(tim_base), 2000, addr2isr_lut[tim_base])


def tim_base_stop_it(uc):
    tim_obj = uc.reg_read(UC_ARM_REG_R0)
    tim_base = bytes2int(uc.mem_read(tim_obj, 4))
    Timer.stop_timer(hex(tim_base))


def tim_irq_handler(uc):
    #tim_obj = uc.reg_read(UC_ARM_REG_R0)
    #tim_base = bytes2int(uc.mem_read(tim_obj, 4))
    #log.info("TICK: Timer %#08x" % tim_base)
    # Call HAL_TIM_PeriodElapsedCallback
    # TODO: Tims can do other things besides elapse.
    # When we see a tim doing that, put it here
    # Leave the regs unchanged, as they should be correct.
    uc.reg_write(UC_ARM_REG_PC, uc.symbols['HAL_TIM_PeriodElapsedCallback'] | 1)

