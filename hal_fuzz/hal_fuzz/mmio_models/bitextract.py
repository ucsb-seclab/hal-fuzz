from ..util import int2bytes, ensure_rw_mapped
from .. import native
from ..globs import MMIO_HOOK_PC_ALL_ACCESS_SITES

def register_bitextract_mmio_models(uc, starts, ends, pcs, byte_sizes, left_shifts, masks):
    for start, end in zip(starts, ends):
        ensure_rw_mapped(uc, start, end)

    native.register_bitextract_mmio_models(uc, starts, ends, pcs, byte_sizes, left_shifts, masks)

def parse_bitextract_handlers(declarations):
    starts, ends, byte_sizes, left_shifts, masks, pcs = [], [], [], [], [], []
    for entry in declarations.values():
        assert (
            'addr' in entry
            # 'size' in entry and
            # 'mask' in entry
        )
        address = entry['addr']
        pc = entry['pc'] if 'pc' in entry else MMIO_HOOK_PC_ALL_ACCESS_SITES
        left_shift = entry['left_shift'] if 'left_shift' in entry else 0
        byte_size = entry['size'] if 'size' in entry else 0
        mask = entry['mask'] if 'mask' in entry else (2**(8*byte_size))-1

        starts.append(address)
        ends.append(address)
        byte_sizes.append(byte_size)
        left_shifts.append(left_shift)
        masks.append(mask)
        pcs.append(pc)

    return starts, ends, pcs, byte_sizes, left_shifts, masks
