from unicorn import UC_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ_INVALID, UC_HOOK_MEM_WRITE_UNMAPPED
from unicorn.arm_const import UC_ARM_REG_PC
from .handlers.fuzz import get_fuzz
from .util import bytes2int
from .exit import add_exit_hook
from .tracing.trace_ids import next_event_id
from .tracing.trace_mem import register_mmio_access_handler

def mem_hook_fuzz_mmio_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        # print("        >>>MMIO Write: addr= 0x{0:016x} size={1} data=0x{2:016x}".format(address, size, value))
        pass
    else:
        fuzzed_bytes = get_fuzz(size)
        uc.mem_write(address, fuzzed_bytes)
        value = bytes2int(fuzzed_bytes)
        # print("        >>>MMIO Read: addr= 0x{0:016x} size={1} ret=0x{2:x}".format(address, size, value))
    
MAX_EXTRA_PAGES=32
num_extra_pages = 0
def unicorn_unmapped_mem_access(uc, access, address, size, value, user_data):
    global num_extra_pages
    if num_extra_pages < MAX_EXTRA_PAGES:
        num_extra_pages += 1
        page_start = address & (~0xfff)
        page_end = page_start + 0x1000
        print("[-] WARNING: mapping new page at 0x{:08x}".format(page_start))
        uc.mem_map(page_start, 0x1000, 3)
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, mem_hook_fuzz_mmio_access, None, page_start, page_end)

        # Add tracing handler for new region
        register_mmio_access_handler(uc, page_start, page_end)
        return True

def register_access_handler(uc, trace_file, config):
    uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ, mem_hook_fuzz_mmio_access, None, config['memory_map']['mmio']['base_addr'], config['memory_map']['mmio']['base_addr'] + config['memory_map']['mmio']['size'])

def register_unmapped_access_handler(uc, max_extra_dynamic_pages):
    global MAX_EXTRA_PAGES
    MAX_EXTRA_PAGES = max_extra_dynamic_pages
    uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID, unicorn_unmapped_mem_access)
