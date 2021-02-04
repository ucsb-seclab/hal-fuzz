from unicorn.arm_const import *
from unicorn.unicorn_const import *
from ...util import crash, crash_memory

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
    # return res

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

    result = _calc_retaddr(base_addr, size+PAGE_SIZE)
    # print(result)
    allocated_chunks[result] = (base_addr-PAGE_SIZE, aligned_size+PAGE_SIZE+PAGE_SIZE)
    print(allocated_chunks[result])
    
    if base_addr == wilderness:
        uc.mem_map(wilderness, aligned_size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_map(wilderness-PAGE_SIZE, PAGE_SIZE, UC_PROT_NONE)
        uc.mem_map(wilderness+aligned_size, PAGE_SIZE, UC_PROT_NONE)

        wilderness += aligned_size + PAGE_SIZE + PAGE_SIZE
    else:
        uc.mem_protect(base_addr, aligned_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(base_addr, b'\xfa'*aligned_size)

    return result

def _free(uc, addr):
    if addr not in allocated_chunks:
        print("Double or arbitrary free detected, crashing")
        crash()
    try:
        allocated_chunks[addr] = base_addr-PAGE_SIZE, aligned_size+PAGE_SIZE+PAGE_SIZE
        uc.mem_write(base_addr, b'\xfd'*aligned_size+PAGE_SIZE+PAGE_SIZE)
    except:
        crash_memory(addr)
    if aligned_size not in free_chunks:
        free_chunks[aligned_size] = [base_addr]
    else:
        free_chunks[aligned_size].append(base_addr)
    # del allocated_chunks[addr]

    # uc.mem_protect(base_addr, aligned_size, UC_PROT_NONE)

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
        uc.mem_write(tar_addr, bytes(curr_contents))
    else:
        # need to allocate new one
        _free(uc, addr)
        tar_addr = _malloc(uc, size)
        uc.mem_write(tar_addr, bytes(curr_contents))
    
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
    #print("res is",res)
    uc.reg_write(UC_ARM_REG_R0, res)
    print("RedZonemalloc. size=0x{:x} -> 0x{:x}".format(PAGE_SIZE, res-PAGE_SIZE))
    print("malloc. size=0x{:x} -> 0x{:x}".format(size, res))
    print("RedZonemalloc. size=0x{:x} -> 0x{:x}".format(PAGE_SIZE, res+size+PAGE_SIZE))

def memp_free(uc):
    addr = uc.reg_read(UC_ARM_REG_R1)
    _free(uc, addr)

def mem_free(uc):
    free(uc)

def mem_malloc(uc):
    # TODO: alignment guarantees
    malloc(uc)


def memcpy(uc):
    dest = uc.reg_read(UC_ARM_REG_R0)
    src = uc.reg_read(UC_ARM_REG_R1)
    n = uc.reg_read(UC_ARM_REG_R2)
    print("memcpy. size=0x{:x} : 0x{:x} -> 0x{:x}".format(n, src, dest))
    res = _memcpy(uc, dest, src, n)
    uc.reg_write(UC_ARM_REG_R0, res)

def _memcpy(uc, dest, src, n):
    # if not dest or not src:
    #     print("Invalid memory write, crashing")
    #     print("Null pointer dereference (dest= 0x{:x}, src= 0x{:x})".format(dest, src))
    #     crash_memory(dest)

    base_addr , aligned_size = (0, 0)
    for chunk in allocated_chunks:
        addr, s = allocated_chunks[chunk]
        # memcpy can be used as 'memcpy(buff+0x10, src, 0x10)'
        # so find chunk that contain destination address
        if addr <= dest and dest < addr + s:
            base_addr = addr
            aligned_size = s
            break
    
    if not base_addr:
        # memcpy from stack to stack
        content = uc.mem_read(src, n)
        try:
            uc.mem_write(dest, bytes(content))
            return dest
        except:
            crash_memory(src)

    curr_size = base_addr + aligned_size - dest
    if curr_size < n:
        print("Heap based overflow detected, crashing")
        print("(dest buf size= 0x{:x}, length to copy= 0x{:x})".format(curr_size, n))
        crash()
    else:
        content = uc.mem_read(src, n)
        
        if content == b'\xfa'*n:
            print("Using not initialized memory detected, crashing")
            crash()
        elif content == b'\xfd'*n:
            # maybe using freed memory is detected by harness.py
            print("Use after free detected, crashing")
            crash()

        content = uc.mem_read(dest, n)
        
        if content == b'\xfd'*n:
            # maybe using freed memory is detected by harness.py
            print("Use after free detected, crashing")
            crash()

        uc.mem_write(dest, bytes(content))

    return base_addr

def func1(uc):
    print('------- Hello Func1 -------')

def vuln(uc):
    print('-------- WARNING --------')
    print('** Vulnerable function **')