mmio_range_added_hooks = []

def add_new_mmio_region_added_callback(hook):
    global mmio_range_added_hooks

    mmio_range_added_hooks.append(hook)


def new_mmio_region_added_callback(start, end):
    for hook in mmio_range_added_hooks:
        hook(start, end)