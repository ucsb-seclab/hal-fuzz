

import sys
import os

exit_hooks = []

def add_exit_hook(fn):
    exit_hooks.append(fn)

def do_exit(status, kill_signal=-1):
    """
    Common exit hook. Be aware that this function is called from within the
    native hooks so any change in prototype has to be reflected
    1. In the native code itself
    2. In the construction of the C-callable function object
    """
    global exit_hooks

    from .globs import debug_enabled, uc

    for fn in exit_hooks:
        if debug_enabled:
            print("Calling exit hook {}".format(exit_hooks))
        try:
            fn(uc)
        except:
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    if kill_signal == -1:
        print("Exiting via os._exit")
        os._exit(status)
    else:
        print("Exiting via os.kill")
        os.kill(os.getpid(), kill_signal)

