from unicorn import UC_MEM_WRITE, UC_HOOK_MEM_READ_AFTER, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ_INVALID, UC_HOOK_MEM_WRITE_UNMAPPED
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR
from .trace_ids import next_event_id
from ..exit import add_exit_hook
from . import add_new_mmio_region_added_callback
from .serialization import dump_mem_line

mmio_outfile = None
ram_outfile = None

mmio_events = []
ram_events = []

def mem_hook_trace_mmio_access(uc, access, address, size, value, user_data):
    mmio_events.append((next_event_id(), uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_LR), "w" if access == UC_MEM_WRITE else "r", size, address, value))

def mem_hook_trace_ram_access(uc, access, address, size, value, user_data):
    ram_events.append((next_event_id(), uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_LR), "w" if access == UC_MEM_WRITE else "r", size, address, value))

def dump_mmio_access_events(uc):
    dump_mem_access_events(uc, mmio_outfile, mmio_events)

def dump_ram_access_events(uc):
    dump_mem_access_events(uc, ram_outfile, ram_events)

def dump_mem_access_events(uc, outfile, events):
    last_mode, last_size, last_address, last_pc, last_lr = None, None, None, None, None
    values = []
    pl = ""
    for event_id, pc, lr, mode, size, address, value in events:
        #print("Writing mode: {}, size: {}, address: {:x}, val: {:x}".format(mode, size, address, value))
        if last_mode is not None:
            values.append(value)
            if not(address == last_address and mode == last_mode and size == last_size and pc == last_pc and lr == last_lr):
                # We got a new line, dump it
                line = dump_mem_line(event_id, pc, lr, mode, size, address, values)
                pl += line + "\n"
                values = []

        last_mode = mode
        last_size = size
        last_address = address
        last_pc = pc
        last_lr = lr

    with open(outfile, "w") as f:
        f.write(pl)

def new_mmio_region_added_callback(start, end):
    from ..globs import uc
    if mmio_outfile is not None:
        print("[+] Acknowledged new mmio region having been added!")
        register_mmio_access_handler(uc, start, end) 

def register_mmio_access_handler(uc, start, end):
    global mmio_outfile
    
    if mmio_outfile is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_trace_mmio_access, None, start, end)

def register_ram_access_handler(uc, start, end):
    global ram_outfile

    if ram_outfile is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_trace_ram_access, None, start, end)

def init_mmio_tracing(uc, trace_file, ranges):
    global mmio_outfile

    if trace_file is not None:
        add_new_mmio_region_added_callback(new_mmio_region_added_callback)

        mmio_outfile = trace_file
        
        for start, end in ranges:
            print("Tracing mmio accesses from 0x{:08x} to 0x{:08x}".format(start, end))
            register_mmio_access_handler(uc, start, end)
        
        add_exit_hook(dump_mmio_access_events)

STACK_SIZE=0x1000
def init_ram_tracing(uc, trace_file, config):
    global ram_outfile

    if trace_file is not None:
        ram_outfile = trace_file

        # trace RAM excluding stack memory
        for region_name in config['memory_map']:
            if 'ram' in region_name.lower():
                start = config['memory_map']['ram']['base_addr']
                end = config['initial_sp'] - STACK_SIZE

                print("Tracing ram accesses from 0x{:08x} to 0x{:08x}".format(start, end))
                register_ram_access_handler(uc, start, end)
        add_exit_hook(dump_ram_access_events)
