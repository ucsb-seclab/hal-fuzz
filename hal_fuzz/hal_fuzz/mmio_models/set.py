from ..util import int2bytes, ensure_rw_mapped
from .. import native
from ..globs import MMIO_HOOK_PC_ALL_ACCESS_SITES

def register_value_set_mmio_models(uc, starts, ends, pcs, val_lists):
    for start, end in zip(starts, ends):
        ensure_rw_mapped(uc, start, end)

    native.register_value_set_mmio_models(uc, starts, ends, pcs, val_lists)

def parse_value_set_handlers(declarations):
    starts, ends, val_lists, pcs = [], [], [], []
    for entry in declarations.values():
        assert (
            'addr' in entry and
            'vals' in entry and
            'pc' in entry
        )
        address = entry['addr']
        pc = entry['pc']
        vals = entry['vals']

        starts.append(address)
        ends.append(address)
        val_lists.append(vals)
        pcs.append(pc)

    return starts, ends, pcs, val_lists
