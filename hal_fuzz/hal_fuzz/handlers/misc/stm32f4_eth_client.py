from unicorn.arm_const import *

button_clicked = False
def inject_button_click_once(uc):
    global button_clicked

    if not button_clicked:
        button_clicked = True
        uc.reg_write(UC_ARM_REG_PC, uc.symbols['HAL_GPIO_EXTI_Callback'])
        uc.reg_write(UC_ARM_REG_R0, 0x2000)

now = 0
def HAL_GetTick(uc):
    global now

    now += 1000
    uc.reg_write(UC_ARM_REG_R0, now)