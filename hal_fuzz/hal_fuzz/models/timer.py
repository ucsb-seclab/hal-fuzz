from . import register_model, Model
from .. import nvic
from .. import native
from ..globs import debug_enabled
from unicorn import UC_HOOK_BLOCK
from unicorn.arm_const import UC_ARM_REG_PC
import sys
from ..handlers import add_func_hook, remove_func_hook
import importlib
from ..exit import do_exit

DEFAULT_TIMER_RELOAD_VAL = 0x1000

def timer_start_block_hook(uc):
    address = uc.reg_read(UC_ARM_REG_PC)
    if address in Timer.delayed_timers:
        # Remove the timer along the way
        for timer_id in Timer.delayed_timers.pop(address):
            print("Starting delayed timer '{}' at {:08x}".format(timer_id, address))
            Timer.resume_timer(timer_id)

        # We only ever want to do start the timer once
        remove_func_hook(address, timer_start_block_hook)


def central_timer_hook(uc, internal_timer_id, userdata):
    Timer.trigger_timer(uc, internal_timer_id)

class Timer(Model):
    callbacks = {}
    internal_indices = {}
    # map {start_at_1: [timer_id_1, timer_id_2], start_at_2: [timer_id_x]}
    delayed_timers = {}

    @classmethod
    def ticks(cls):
        return native.get_global_ticker()

    @classmethod
    def configure(cls, uc, config):
        if 'use_timers' in config and config['use_timers'] is True:
            if 'global_timer_scale' in config:
                global_timer_scale = config['global_timer_scale']
            else:
                global_timer_scale = 1
            native.init_timer_hook(uc, global_timer_scale)

            # Parse config for timer function handlers
            if 'timers' in config:
                for timer_id, timer_config in config['timers'].items():
                    if 'reload_val' in timer_config:
                        reload_val = timer_config['reload_val']
                    else:
                        reload_val = DEFAULT_TIMER_RELOAD_VAL
                        print("[WARNING] did not find 'reload_val' for timer '{}', assigning default of {}".format(timer_id, reload_val))

                    if 'handler' in timer_config:
                        # Register handler function
                        func = timer_config['handler']

                        try:
                            # Resolve the function name
                            mod_name, func_name = func.rsplit('.', 1)
                            mod = importlib.import_module(mod_name)
                            func_obj = getattr(mod, func_name)
                        except:
                            import traceback
                            print("Unable to hook function %s for timer %r" % (repr(func), timer_id))
                            traceback.print_exc()
                            do_exit(1)
                        timer_func_irq = func_obj
                    elif 'irq' in timer_config:
                        # Register with an irq number
                        timer_func_irq = timer_config['irq']
                    else:
                        print("[Timer Config ERROR] For a timer configuration, either 'irq' or 'handler' is required")
                        exit(-1)

                    cls.start_timer(timer_id, reload_val, timer_func_irq)

                    # See if there is a particular address in the firmware execution to start the timer at
                    if 'start_at' in timer_config:
                        cls.stop_timer(timer_id)
                        addr = timer_config['start_at']
                        if not cls.delayed_timers:
                            add_func_hook(uc, addr, timer_start_block_hook, do_return=False)
                        if addr not in cls.delayed_timers:
                            cls.delayed_timers[addr] = []
                        cls.delayed_timers[addr].append(timer_id)

    @classmethod
    def start_timer(cls, timer_id, timer_rate, timer_func_irq):
        """
        Start a timer.

        :param timer_id: The 'id' of the timer.  This is either its name, or a base address.
        Generally anything we need to identify that timer again later.
        :param timer_rate:  The timer's 'rate', in ticks. After this many ticks, the event will occur.
        :param timer_func_irq: What to do when the timer elapses.  If this is an int, inject that interrupt.  If it
        is a function object, just call that instead.
        :return:
        """
        assert(timer_id not in cls.internal_indices)
        if isinstance(timer_func_irq, int):
            internal_ind = native.add_timer(timer_rate, isr_num=timer_func_irq)
        else:
            internal_ind = native.add_timer(timer_rate, callback=timer_func_irq)
            cls.callbacks[internal_ind] = timer_func_irq

        cls.internal_indices[timer_id] = internal_ind

        print("Starting timer %s with rate %s (internal id: %d)" % (repr(timer_id), timer_rate, internal_ind))
        return internal_ind

    @classmethod
    def timer_exists(cls, timer_id):
        return timer_id in cls.internal_indices

    @classmethod
    def stop_timer(cls, timer_id):
        print("Stopping timer %s" % repr(timer_id))
        if timer_id not in cls.internal_indices:
            print("UH OH: We never started timer %s" % repr(timer_id))
            return
        native.stop_timer(cls.internal_indices[timer_id])

    @classmethod
    def is_running(cls, timer_id):
        if timer_id not in cls.internal_indices:
            print("UH OH: We never created timer %s" % repr(timer_id))
            return False
        return native.is_running(cls.internal_indices[timer_id])

    @classmethod
    def resume_timer(cls, timer_id):
        print("Resuming timer %s" % repr(timer_id))
        if timer_id not in cls.internal_indices:
            print("UH OH: We never started timer %s" % repr(timer_id))
            return
        native.start_timer(cls.internal_indices[timer_id])

    @classmethod
    def reset_timer(cls, timer_id):
        if timer_id not in cls.internal_indices:
            print("UH OH: We never started timer %s" % repr(timer_id))
            return
        native.reset_timer(cls.internal_indices[timer_id])

    @classmethod
    def trigger_timer(cls, uc, internal_timer_id):
        cls.callbacks[internal_timer_id](uc)

register_model(Timer)