from unicorn.arm_const import *
from ...util import bytes2int, int2bytes
from ...models.ethernet import EthernetModel
from ...globs import debug_enabled

import struct

# ETH_HandleTypeDef: http://www.disca.upv.es/aperles/arm_cortex_m3/llibre/st/STM32F439xx_User_Manual/structeth__handletypedef.html
OFF_RX_DESC = 40
OFF_TX_DESC = 44
OFF_DMA_RX_FRAME_INFOS = 48
# ETH_InitTypeDef (size: 32) : http://www.disca.upv.es/aperles/arm_cortex_m3/llibre/st/STM32F439xx_User_Manual/structeth__inittypedef.html
# ETH_DMADescTypeDef: http://www.disca.upv.es/aperles/arm_cortex_m3/llibre/st/STM32F439xx_User_Manual/structeth__dmadesctypedef.html
OFF_DMA_DESC_BUF_1_ADDR = 8
OFF_DMA_DESC_BUG_2_NEXT_DESC_ADDR = 12

phy_regs = {1:0x786d, 0x10:0x115, 0x11:0, 0x12:0x2c00}

# HAL_StatusTypeDef 	HAL_ETH_TransmitFrame (ETH_HandleTypeDef *heth, uint32_t FrameLength)
def HAL_ETH_TransmitFrame(uc):
    if debug_enabled:
        print("HAL_ETH_TransmitFrame")
    heth = uc.reg_read(UC_ARM_REG_R0)
    frame_len = uc.reg_read(UC_ARM_REG_R1)

    tx_desc = bytes2int(uc.mem_read(heth + OFF_TX_DESC, 4))
    tx_frame = bytes2int(uc.mem_read(tx_desc + OFF_DMA_DESC_BUF_1_ADDR, 4))
    contents = uc.mem_read(tx_frame, frame_len)

    EthernetModel.tx_frame(bytes2int(uc.mem_read(heth, 4)), contents)

    uc.reg_write(UC_ARM_REG_R0, 0)
    

# HAL_StatusTypeDef 	HAL_ETH_GetReceivedFrame (ETH_HandleTypeDef *heth)
def HAL_ETH_GetReceivedFrame(uc):
    if debug_enabled:
        print("HAL_ETH_GetReceivedFrame")
    heth = uc.reg_read(UC_ARM_REG_R0)
    interface_id = bytes2int(uc.mem_read(heth, 4))

    contents = EthernetModel.get_rx_frame(interface_id)
    
    rx_desc = bytes2int(uc.mem_read(heth+OFF_RX_DESC, 4))
    next_desc_addr = bytes2int(uc.mem_read(rx_desc + OFF_DMA_DESC_BUG_2_NEXT_DESC_ADDR, 4))
    desc_buf_addr = bytes2int(uc.mem_read(next_desc_addr + OFF_DMA_DESC_BUF_1_ADDR, 4))
    frame_info = struct.pack("<IIIII", rx_desc, rx_desc, 1, len(contents), desc_buf_addr)
    uc.mem_write(heth + OFF_DMA_RX_FRAME_INFOS, frame_info)
    uc.mem_write(desc_buf_addr, contents)
    uc.mem_write(heth + OFF_RX_DESC, int2bytes(next_desc_addr))

    uc.reg_write(UC_ARM_REG_R0, 0)

# HAL_StatusTypeDef 	HAL_ETH_WritePHYRegister (ETH_HandleTypeDef *heth, uint16_t PHYReg, uint32_t RegValue)
def HAL_ETH_WritePHYRegister(uc):
    # heth = uc.reg_read(UC_ARM_REG_R0)
    phy_reg = uc.reg_read(UC_ARM_REG_R1)
    reg_val = uc.reg_read(UC_ARM_REG_R2)
    phy_regs[phy_reg] = reg_val
    if debug_enabled:
        print("HAL_ETH_WritePHYRegister [0x{:x}] = 0x{:x}".format(phy_reg, reg_val))

    uc.reg_write(UC_ARM_REG_R0, 0)

# HAL_StatusTypeDef 	HAL_ETH_ReadPHYRegister (ETH_HandleTypeDef *heth, uint16_t PHYReg, uint32_t *RegValue)
def HAL_ETH_ReadPHYRegister(uc):
    # heth = uc.reg_read(UC_ARM_REG_R0)
    phy_reg = uc.reg_read(UC_ARM_REG_R1)
    reg_ptr = uc.reg_read(UC_ARM_REG_R2)

    if phy_reg in phy_regs:
        reg_val = phy_regs[phy_reg]
    else:
        reg_val = 0
    uc.mem_write(reg_ptr, int2bytes(reg_val))

    if debug_enabled:
        print("HAL_ETH_ReadPHYRegister [0x{:x}] = 0x{:x}".format(phy_reg, reg_val))
    uc.reg_write(UC_ARM_REG_R0, 0)
