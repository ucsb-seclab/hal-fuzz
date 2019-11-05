from ..util import int2bytes, ensure_rw_mapped
from .. import native
from ..globs import MMIO_HOOK_PC_ALL_ACCESS_SITES

curr_vals = {}

def mmio_access_handler_linear_values(uc, access, address, size, value, user_data):
    curr_val, step = curr_vals[address]
    pl = int2bytes(curr_val)
    # print("Linear callback called! Writing 0x{:08x} to 0x{:08x}".format(curr_val, address))
    uc.mem_write(address, pl)

    curr_vals[address][0] = (curr_val + step) & 0xffffffff
    return True

def register_linear_mmio_models(uc, starts, ends, pcs, init_vals, steps):
    for start, end in zip(starts, ends):
        ensure_rw_mapped(uc, start, end)

    native.register_linear_mmio_models(uc, starts, ends, pcs, init_vals, steps)

def parse_linear_handlers(declarations):
    starts, ends, pcs, init_vals, steps = [], [], [], [], []
    for entry in declarations.values():
        assert (
            'addr' in entry and
            entry['addr'] % 4 == 0 and
            'step' in entry
        )
        init_val = entry['init_val'] if 'init_val' in entry else 0
        address = entry['addr']
        step = entry['step']
        # We don't use pc context for linear models for now
        pc = MMIO_HOOK_PC_ALL_ACCESS_SITES

        starts.append(address)
        ends.append(address)
        init_vals.append(init_val)
        steps.append(step)
        pcs.append(pc)

    return starts, ends, pcs, init_vals, steps