from unicorn.arm_const import *
from unicorn.unicorn_const import *
from ...util import crash

"""
Quick and unoptimized implementation of dynamic memory management allowing to
detect UAF, double free, heap overflow and some heap underflow issues.
"""

wilderness = 0xff000000
free_chunks = {}
allocated_chunks = {}
PAGE_SIZE = 0x1000

def _calc_aligned_size(size):
    res = size + (PAGE_SIZE - size % PAGE_SIZE)
    # TODO: alignment guarantees
    #if res % 4 != 0:
    #    res += (4 - (res % 4))
    return res

def _calc_retaddr(baseaddr, size):
    return baseaddr + _calc_aligned_size(size) - size

def _malloc(uc, size):
    global wilderness
    
    aligned_size = _calc_aligned_size(size)

    # Non-empty list in free_chunks?
    if aligned_size in free_chunks and free_chunks[aligned_size]:
        base_addr = free_chunks[aligned_size].pop()
    else:
        base_addr = wilderness

    result = _calc_retaddr(base_addr, size)
    
    allocated_chunks[result] = (base_addr, aligned_size)
    
    if base_addr == wilderness:
        uc.mem_map(wilderness, aligned_size, UC_PROT_READ | UC_PROT_WRITE)
        wilderness += aligned_size + PAGE_SIZE
    else:
        uc.mem_protect(base_addr, aligned_size, UC_PROT_READ | UC_PROT_WRITE)

    return result

def _free(uc, addr):
    if addr not in allocated_chunks:
        print("Double or arbitrary free detected, crashing")
        crash()

    base_addr, aligned_size = allocated_chunks[addr]
    if aligned_size not in free_chunks:
        free_chunks[aligned_size] = [base_addr]
    else:
        free_chunks[aligned_size].append(base_addr)
    del allocated_chunks[addr]

    uc.mem_protect(base_addr, aligned_size, UC_PROT_NONE)

def _calloc(uc, size):
    res = _malloc(uc, size)
    uc.mem_write(res, size * b'\0')
    return res

def _realloc(uc, addr, size):
    if addr not in allocated_chunks:
        print("Invalid realloc detected, crashing")
        crash()

    base_addr, aligned_size = allocated_chunks[addr]
    curr_size = base_addr + aligned_size - addr
    curr_contents = uc.mem_read(addr, curr_size)
    # TODO: handle the case of buffer being adjacent to wilderness
    if aligned_size >= size:
        # reuse buffer
        tar_addr = _calc_retaddr(base_addr, size)
        uc.mem_write(tar_addr, curr_contents)
    else:
        # need to allocate new one
        _free(uc, addr)
        tar_addr = _malloc(uc, size)
        uc.mem_write(tar_addr, curr_contents)
    
    return tar_addr

def free(uc):
    addr = uc.reg_read(UC_ARM_REG_R0)
    print("freeing 0x{:x}".format(addr))
    if addr != 0:
        _free(uc, addr)

def calloc(uc):
    size = uc.reg_read(UC_ARM_REG_R0)
    res = _calloc(uc, size)
    uc.reg_write(UC_ARM_REG_R0, res)
    print("malloc. size=0x{:x} -> 0x{:x}".format(size, res))

def realloc(uc):
    addr = uc.reg_read(UC_ARM_REG_R0)
    size = uc.reg_read(UC_ARM_REG_R1)
    print("realloc. addr: 0x{:x}, size=0x{:x}".format(addr, size))
    res = _realloc(uc, addr, size)
    uc.reg_write(UC_ARM_REG_R0, res)


def malloc(uc):
    size = uc.reg_read(UC_ARM_REG_R0)
    res = _malloc(uc, size)
    uc.reg_write(UC_ARM_REG_R0, res)
    print("malloc. size=0x{:x} -> 0x{:x}".format(size, res))
    
def memp_free(uc):
    addr = uc.reg_read(UC_ARM_REG_R1)
    _free(uc, addr)

def mem_free(uc):
    free(uc)

def mem_malloc(uc):
    # TODO: alignment guarantees
    malloc(uc)