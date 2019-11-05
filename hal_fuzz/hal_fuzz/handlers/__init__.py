from .. import nvic
from ..globs import debug_enabled
from .. import globs
from ..exit import do_exit
from unicorn import UC_HOOK_BLOCK

import importlib
import sys

func_hooks = {}

def remove_func_hook(address, func):
    assert ((address in func_hooks) and func in func_hooks[address])
    func_hooks[address].remove(func)
    # is the address fully gone?
    if not func_hooks[address]:
        del func_hooks[address]
        from .. import native
        native.remove_function_handler_hook_address(globs.uc, address)

def add_func_hook(uc, addr, func, do_return=True):
    """
    Add a function hook.

    If func is None (and do_return is True) this is effectively a nop-out without using a real hook!
    Makes it faster to not have to call into python for hooks we don't need.
    """

    real_addr = addr & 0xFFFFFFFE  # Drop the thumb bit
    if func:
        if isinstance(func, str):
            try:
                # Resolve the function name
                mod_name, func_name = func.rsplit('.', 1)
                mod = importlib.import_module(mod_name)
                func_obj = getattr(mod, func_name)
            except:
                import traceback
                print("Unable to hook function %s at address %#08x" % (repr(func), addr))
                traceback.print_exc()
                do_exit(1)
        else:
            func_obj = func

        if real_addr not in func_hooks:
            func_hooks[real_addr] = []
        func_hooks[real_addr].append(func_obj)

    if do_return:
        # TODO: Make this arch-independent.  Hint, use archinfo
        bxlr = b'\x70\x47'
        uc.mem_write(real_addr, bxlr)


def func_hook_handler(uc, addr, size, user_data):
    if addr in func_hooks:
        for hook in func_hooks[addr]:
            if debug_enabled:
                print("Calling hook %s at %#08x" % (func_hooks[addr].__name__, addr))
            try:
                hook(uc)
            except:
                import traceback
                traceback.print_exc()
                do_exit(1)

def register_func_handler_hook():
    if func_hooks:
        print("Registering function hook for {} handlers".format(sum([len(funcs) for funcs in func_hooks.values()])))
        add_block_hook(func_hook_handler)
    else:
        print("No conditional non-native block hooks configured, skipping basic block registration")


block_hooks = []

def add_block_hook(hook):
    block_hooks.append(hook)

def register_global_block_hook(uc):
    if block_hooks:
        print("Registering block hook wrapper for {} hooks: {}".format(len(block_hooks), block_hooks))
        uc.hook_add(UC_HOOK_BLOCK, block_hook_handler)
    else:
        print("No non-native unconditional basic block hooks registered, not adding global hook")

def block_hook_handler(uc, address, size, user_data):
    for hook in block_hooks:
        hook(uc, address, size, user_data)
