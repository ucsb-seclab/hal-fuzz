from . import native

def init_triggers(uc, entries):
    for entry in entries.values():
        addr = entry['address'] if 'address' in entry else entry['addr']
        irq = entry['irq']
        num_skips = entry['num_skips'] if 'num_skips' in entry else 0
        num_pends = entry['num_pends'] if 'num_pends' in entry else 1
        do_fuzz = entry['fuzz'] if 'fuzz' in entry else False

        native.add_interrupt_trigger(uc, addr, irq, num_skips, num_pends, do_fuzz)