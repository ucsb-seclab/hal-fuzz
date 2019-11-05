import sys
from unicorn.arm_const import *
from ...util import *
import sys
from ..fuzz import fuzz_remaining, get_fuzz
from ...models.i2c import I2CModel


def HAL_I2C_Init(uc):
    pass


def HAL_I2C_Mem_Read(uc):
    # HAL_StatusTypeDef __fastcall HAL_I2C_Mem_Read(I2C_HandleTypeDef *hi2c, uint16_t DevAddress, uint16_t MemAddress, uint16_t MemAddSize, uint8_t *pData, uint16_t Size, uint32_t Timeout)
    device_id = uc.reg_read(UC_ARM_REG_R0)
    dev_addr = uc.reg_read(UC_ARM_REG_R1)
    mem_addr = uc.reg_read(UC_ARM_REG_R2)
    mem_addr_size = uc.reg_read(UC_ARM_REG_R3)
    dst_buf = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
    dst_buf_size = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP) + 0x4, 4))[0]
    timeout = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP) + 0x8, 4))[0]
    assert(dst_buf != 0)
    assert(dst_buf_size < 1000)
    assert(mem_addr < 65535)
    assert(dst_buf_size >= mem_addr_size)
    #stuff = I2CModel.rx(device_id, dev_addr, mem_addr_size)
    stuff = get_fuzz(mem_addr_size)
    uc.mem_write(dst_buf, stuff)
    uc.reg_write(UC_ARM_REG_R0, 0)
    print(b"<<< " + stuff)


def HAL_I2C_Mem_Write(uc):
    uc.reg_write(UC_ARM_REG_R0, 0)
