from unicorn import *
from unicorn.arm_const import *
import ctypes
import os
import sys
from os import path
from .exit import do_exit
from .models import timer

native_lib = None
mmio_cb_wrapper = None
timer_cb_wrapper = None
timer_cb_user_data = None

# just like unicorn does we need to keep references to ctype cb objects
obj_refs = []

uc_engine = ctypes.c_void_p
# Prototyping code taken from unicorn python bindings
def _load_lib(path):
    try:

        lib_file = os.path.join(path)
        print('Trying to load shared library', lib_file)
        dll = ctypes.cdll.LoadLibrary(lib_file)
        print('SUCCESS')
        return dll
    except OSError as e:
        print('FAIL to load %s' %lib_file, e)
        return None

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

EXIT_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_int, ctypes.c_int
)

MMIO_REGION_ADDED_CB = ctypes.CFUNCTYPE(
    None, ctypes.c_uint64, ctypes.c_uint64
)

UC_HOOK_CODE_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p
)

UC_HOOK_MEM_ACCESS_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)

UC_HOOK_INTR_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32, ctypes.c_void_p
)


def add_unmapped_mem_hook(uc):
    assert(native_lib.add_unmapped_mem_hook(uc._uch)==0)

def load_fuzz(file_path):
    print("Loading fuzz from: {}".format(file_path))
    assert(native_lib.load_fuzz(file_path.encode())==0)
    print('lol')
    sys.stdout.flush()

def get_fuzz(size):
    ptr = (ctypes.c_char * size).from_address(native_lib.get_fuzz_ptr(size))
    return ptr.raw

def fuzz_remaining():
    return native_lib.fuzz_remaining()

def register_cond_py_handler_hook(uc, handler_locs):
    if not handler_locs:
        print("no function handler hooks registered, skipping registration")
        return

    arr = (ctypes.c_int64 * len(handler_locs))(*handler_locs)
    
    # hack: In order to keep a uc reference around for the high level callback,
    # we sneak an additional callback into the uc object (as done in unicorn.py)
    from .handlers import func_hook_handler
    callback = func_hook_handler
    uc._callback_count += 1
    uc._callbacks[uc._callback_count] = (callback, None)
    cb = ctypes.cast(UC_HOOK_CODE_CB(uc._hookcode_cb), UC_HOOK_CODE_CB)
    user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)

    assert(native_lib.register_cond_py_handler_hook(
        uc._uch, cb, arr, len(arr), user_data
    ) == 0)
    obj_refs.append(cb)


def remove_function_handler_hook_address(uc, address):
    assert(native_lib.remove_function_handler_hook_address(uc._uch, address) == 0)


def _create_and_inject_c_callable_mem_hook(uc, py_fn):
    # hack: In order to keep a uc reference around for the high level callback,
    # we sneak an additional callback into the uc object (as done in unicorn.py)
    callback = py_fn
    uc._callback_count += 1
    uc._callbacks[uc._callback_count] = (callback, None)
    cb = ctypes.cast(UC_HOOK_MEM_ACCESS_CB(uc._hook_mem_access_cb), UC_HOOK_MEM_ACCESS_CB)
    user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)
    obj_refs.append(cb)
    return cb, user_data


def _create_and_inject_c_callable_central_timer_hook(uc, py_fn):
    callback = py_fn
    # hack: In order to keep a uc reference around for the high level callback,
    # we sneak an additional callback into the uc object (as done in unicorn.py)
    # even bigger hack: we re-use the prototype of interrupt callbacks for the fact of their function prototype
    # to create an alternative callback
    # from: cb(self, intno, data)
    # to  : cb(self, timer_id, data)
    uc._callback_count += 1
    uc._callbacks[uc._callback_count] = (callback, None)
    cb = ctypes.cast(UC_HOOK_INTR_CB(uc._hook_intr_cb), UC_HOOK_INTR_CB)
    user_data = ctypes.cast(uc._callback_count, ctypes.c_void_p)
    obj_refs.append(cb)
    return cb, user_data



def register_linear_mmio_models(uc, starts, ends, pcs, init_vals, steps):
    assert(len(starts) == len(ends) == len(init_vals) == len(steps))
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    init_vals_arr = (ctypes.c_int32 * len(init_vals))(*init_vals)
    steps_arr = (ctypes.c_int32 * len(steps))(*steps)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    assert(native_lib.register_linear_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, init_vals_arr, steps_arr, len(starts)) == 0)


def register_constant_mmio_models(uc, starts, ends, pcs, vals):
    assert(len(starts) == len(ends) == len(vals)==len(pcs))
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    vals_arr = (ctypes.c_int32 * len(vals))(*vals)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    assert(native_lib.register_constant_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, vals_arr, len(starts)) == 0)


def register_bitextract_mmio_models(uc, starts, ends, pcs, byte_sizes, left_shifts, masks):
    assert(len(starts) == len(ends) == len(byte_sizes) == len(left_shifts) == len(pcs))
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    byte_sizes_arr = (ctypes.c_int8 * len(byte_sizes))(*byte_sizes)
    left_shifts_arr = (ctypes.c_int8 * len(left_shifts))(*left_shifts)
    masks_arr = (ctypes.c_int32 * len(masks))(*masks)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    assert(native_lib.register_bitextract_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, byte_sizes_arr, left_shifts_arr, masks_arr, len(starts)) == 0)


def register_value_set_mmio_models(uc, starts, ends, pcs, value_sets):
    assert(len(starts) == len(ends) == len(value_sets) == len(value_sets) == len(pcs))
    starts_arr = (ctypes.c_int64 * len(starts))(*starts)
    ends_arr = (ctypes.c_int64 * len(ends))(*ends)
    pcs_arr = (ctypes.c_int32 * len(pcs))(*pcs)

    value_nums_arr = (ctypes.c_int32 * len(value_sets))(*[len(value_set) for value_set in value_sets])

    value_set_arrs = [(ctypes.c_int32 * len(value_set))(*value_set) for value_set in value_sets]
    value_sets_arr_ptrs = (ctypes.POINTER(ctypes.c_ulong) * len(value_set_arrs))(*[ctypes.cast(value_set_arr, ctypes.POINTER(ctypes.c_ulong)) for value_set_arr in value_set_arrs])

    assert(native_lib.register_value_set_mmio_models(uc._uch, starts_arr, ends_arr, pcs_arr, value_nums_arr, value_sets_arr_ptrs, len(starts)) == 0)


def set_ignored_mmio_addresses(addresses, pcs):
    addrs_arr = (ctypes.c_int64 * len(addresses))(*addresses)
    pcs_arr = (ctypes.c_uint32 * len(pcs))(*pcs)

    assert(native_lib.set_ignored_mmio_addresses(
        addrs_arr, pcs_arr, len(addrs_arr)
    ) == 0)


def init_nvic(uc, vtor, num_vecs, is_oneshot=False):
    global native_lib
    print("Calling init_nvic with vtor=0x{:08x}, num_vecs: {}, is_oneshot: {}".format(vtor, num_vecs, is_oneshot))
    assert ( native_lib.init_nvic(uc._uch, vtor, num_vecs, is_oneshot) == 0)


def nvic_set_pending(vec_num):
    global native_lib
    native_lib.nvic_set_pending(vec_num)


def nvic_enter_exception(uc, vec_num):
    global native_lib
    native_lib.nvic_enter_exception(uc._uch, vec_num)


def init_timer_hook(uc, global_timer_scale):
    global native_lib
    global timer_cb_user_data
    global timer_cb_wrapper

    cb, user_data = _create_and_inject_c_callable_central_timer_hook(uc, timer.central_timer_hook)
    timer_cb_wrapper = cb
    timer_cb_user_data = user_data

    assert(native_lib.init_timer_hook(uc._uch, global_timer_scale) == 0)

IRQ_NOT_USED=0xffffffff
def add_timer(reload_val, callback=None, isr_num=IRQ_NOT_USED):
    global timer_cb_wrapper
    global timer_cb_user_data
    global native_lib

    assert (timer_cb_wrapper is not None and timer_cb_user_data is not None)
    # While technically allowed in the C code, invoking a callback and pending an interrupt at the same time is nothing we would like to support
    assert (not (callback is not None and isr_num != IRQ_NOT_USED))

    passed_cb = timer_cb_wrapper if callback is not None else 0

    return native_lib.add_timer(reload_val, passed_cb, timer_cb_user_data, isr_num)


def is_running(timer_id):
    return native_lib.is_running(timer_id)


def get_global_ticker():
    global native_lib
    return native_lib.get_global_ticker()

def rem_timer(timer_id):
    global native_lib
    assert(native_lib.rem_timer(timer_id) == 0)

def reset_timer(timer_id):
    global native_lib
    assert(native_lib.reset_timer(timer_id) == 0)

def start_timer(timer_id):
    global native_lib
    assert (native_lib.start_timer(timer_id) == 0)

def stop_timer(timer_id):
    global native_lib
    assert (native_lib.stop_timer(timer_id) == 0)

# uc_hook add_interrupt_trigger(uc_engine *uc, uint64_t addr, uint32_t irq, uint32_t num_skips, uint32_t num_pends, uint32_t do_fuzz);
def add_interrupt_trigger(uc, addr, irq, num_skips, num_pends, do_fuzz):
    assert(native_lib.add_interrupt_trigger(uc._uch, addr, irq, num_skips, num_pends, do_fuzz) == 0)

def init(uc, native_lib_path, fuzz_mmio, mmio_regions, max_num_dynamically_added_mmio_pages, exit_at_bbls, allowed_fuzzed_irqs):
    global native_lib
    global mmio_cb_wrapper
    print("Native init...")
    sys.stdout.flush()
    native_lib = _load_lib(native_lib_path)
    assert (native_lib is not None)
    # GENERAL
    # uc_err init(uc_engine *uc, int fuzz_mmio, exit_hook_t p_exit_hook, mmio_region_added_cb_t p_mmio_region_added_cb, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, void *p_py_default_mmio_user_data, int max_num_dynamically_added_mmio_pages, uint32_t num_exit_at_bbls, uint64_t *exit_at_bbls, uint32_t num_allowed_irq_numbers, uint8_t *allowed_irq_numbers);
    _setup_prototype(native_lib, "init", ctypes.c_int, uc_engine, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p)
    # uc_err register_cond_py_handler_hook(uc_cb_hookcode_t py_callback, uint64_t *addrs, int num_addrs)
    _setup_prototype(native_lib, "register_cond_py_handler_hook", ctypes.c_int, uc_engine, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int)
    # uc_err remove_function_handler_hook_address(uc_engine * uc, uint64_t address);
    _setup_prototype(native_lib, "remove_function_handler_hook_address", ctypes.c_int, uc_engine, ctypes.c_uint64)

    # FUZZING
    _setup_prototype(native_lib, "load_fuzz", ctypes.c_int, ctypes.c_char_p)
    # uint32_t fuzz_remaining();
    _setup_prototype(native_lib, "fuzz_remaining", ctypes.c_int)
    # char *get_fuzz_ptr(uint32_t size);
    _setup_prototype(native_lib, "get_fuzz_ptr", ctypes.c_void_p, ctypes.c_uint32)
    # uc_err add_unmapped_mem_hook(uc_engine *uc)
    _setup_prototype(native_lib, "add_unmapped_mem_hook", ctypes.c_int, uc_engine)

    # NVIC
    # extern uc_err init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_vectors, uint32_t is_oneshot)
    _setup_prototype(native_lib, "init_nvic", ctypes.c_int, uc_engine, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint)
    # extern void nvic_set_pending(int num)
    _setup_prototype(native_lib, "nvic_set_pending", ctypes.c_int, ctypes.c_int)
    # extern static void nvic_enter_exception(uc_engine *uc, uint32_t num)
    _setup_prototype(native_lib, "nvic_enter_exception", ctypes.c_int, uc_engine, ctypes.c_uint)


    # TIMER
    # extern uint64_t get_global_ticker();
    _setup_prototype(native_lib, 'get_global_ticker', ctypes.c_int64)
    # extern uc_err init_timer_hook(uc_engine *uc, uint32_t global_timer_scale);
    _setup_prototype(native_lib, "init_timer_hook", ctypes.c_int, uc_engine, ctypes.c_uint)
    # extern uint32_t add_timer(int64_t reload_val, void *trigger_callback, uint32_t isr_num);
    _setup_prototype(native_lib, "add_timer", ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32)
    # extern uc_err rem_timer(uint32_t id);
    _setup_prototype(native_lib, "rem_timer", ctypes.c_int, ctypes.c_uint32)
    # extern uc_err reset_timer(uint32_t id);
    _setup_prototype(native_lib, "reset_timer", ctypes.c_int, ctypes.c_uint32)
    # extern uc_err start_timer(uint32_t id);
    _setup_prototype(native_lib, "start_timer", ctypes.c_int, ctypes.c_uint32)
    # extern uint32_t is_running(uint32_t id)
    _setup_prototype(native_lib, "is_running", ctypes.c_int, ctypes.c_uint32)
    # extern uc_err stop_timer(uint32_t id);
    _setup_prototype(native_lib, "stop_timer", ctypes.c_int, ctypes.c_uint32)

    assert (native_lib.init(uc._uch, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) == 0)
