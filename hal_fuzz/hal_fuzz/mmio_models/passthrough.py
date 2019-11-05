from ..util import int2bytes, ensure_rw_mapped
from ..native import set_ignored_mmio_addresses
from ..globs import MMIO_HOOK_PC_ALL_ACCESS_SITES

def register_passthrough_handlers(uc, declarations):
    addrs = []
    pcs = []
    for entry in declarations.values():
        assert (
            'addr' in entry
        )
        address = entry['addr']
        pc = entry['pc'] if 'pc' in entry else MMIO_HOOK_PC_ALL_ACCESS_SITES
        value = entry['init_val'] if 'init_val' in entry else 0
        if value != 0:
            pl = int2bytes(value)
            uc.mem_write(address, pl)
        
        addrs.append(address)
        pcs.append(pc)

        ensure_rw_mapped(uc, address, address)

    set_ignored_mmio_addresses(addrs, pcs)
