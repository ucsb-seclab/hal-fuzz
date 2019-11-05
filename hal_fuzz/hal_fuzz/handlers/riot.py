from unicorn.arm_const import *
from ..models.timer import Timer
import struct

# This implements the RIOT scheduler.
# TODO: We need the thread timer somewhere.  None of our Riot samples use that, and it won't be too hard to do

riot_threads = []

class RiotThread(object):
    stack = 0 # Pointer, the location of the stack for this thread
    stack_len = 0 # the size of this stack
    flags = 0 # Flags
    priority = 0 # The priority
    name = "" # String name of this thread
    arg = 0 # The arg passed to this thread (void ptr)
    func = 0 # The actual function to execute
    context = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # r0 - r15

cur_riot_thread = None
cur_prio = 0x0


def _riot_context_save(uc, thr):
    thr.context[0] = uc.reg_read(UC_ARM_REG_R0)
    thr.context[1] = uc.reg_read(UC_ARM_REG_R1)
    thr.context[2] = uc.reg_read(UC_ARM_REG_R2)
    thr.context[3] = uc.reg_read(UC_ARM_REG_R3)
    thr.context[4] = uc.reg_read(UC_ARM_REG_R4)
    thr.context[5] = uc.reg_read(UC_ARM_REG_R5)
    thr.context[6] = uc.reg_read(UC_ARM_REG_R6)
    thr.context[7] = uc.reg_read(UC_ARM_REG_R7)
    thr.context[8] = uc.reg_read(UC_ARM_REG_R8)
    thr.context[9] = uc.reg_read(UC_ARM_REG_R9)
    thr.context[10] = uc.reg_read(UC_ARM_REG_R10)
    thr.context[11] = uc.reg_read(UC_ARM_REG_R11)
    thr.context[12] = uc.reg_read(UC_ARM_REG_R12)
    thr.context[13] = uc.reg_read(UC_ARM_REG_SP)
    thr.context[14] = uc.reg_read(UC_ARM_REG_LR)
    thr.context[15] = uc.reg_read(UC_ARM_REG_PC)


def _riot_context_restore(uc, thr):
    uc.reg_write(UC_ARM_REG_R0, thr.context[0])
    uc.reg_write(UC_ARM_REG_R1, thr.context[1])
    uc.reg_write(UC_ARM_REG_R2, thr.context[2])
    uc.reg_write(UC_ARM_REG_R3, thr.context[3])
    uc.reg_write(UC_ARM_REG_R4, thr.context[4])
    uc.reg_write(UC_ARM_REG_R5, thr.context[5])
    uc.reg_write(UC_ARM_REG_R6, thr.context[6])
    uc.reg_write(UC_ARM_REG_R7, thr.context[7])
    uc.reg_write(UC_ARM_REG_R8, thr.context[8])
    uc.reg_write(UC_ARM_REG_R9, thr.context[9])
    uc.reg_write(UC_ARM_REG_R10, thr.context[10])
    uc.reg_write(UC_ARM_REG_R11, thr.context[11])
    uc.reg_write(UC_ARM_REG_R12, thr.context[12])
    uc.reg_write(UC_ARM_REG_SP, thr.context[13])
    uc.reg_write(UC_ARM_REG_LR, thr.context[14])
    uc.reg_write(UC_ARM_REG_PC, thr.context[15])


def riot_sched(uc):
    global riot_threads
    global cur_riot_thread
    global cur_prio
    # TODO: Probably something more complex than this.
    # Save old thread
    if cur_riot_thread is not None:
        _riot_context_save(uc, cur_riot_thread)
    # Get next thread
    next_thread = None
    for pr in range(cur_prio, 0xf):
        for t in riot_threads:
            if t.priority <= pr:
                next_thread = t
                break
        if next_thread is not None:
            break
    if not next_thread:
        next_thread = cur_riot_thread
    print("RIOT: Switching to thread %s(%#08x)" % (next_thread.name, next_thread.func))
    # Put the old thread at the end of the queue
    if cur_riot_thread is not None:
        riot_threads.append(cur_riot_thread)
    # Pop the next thread out of the queue
    riot_threads.remove(next_thread)
    cur_riot_thread = next_thread
    cur_prio = cur_riot_thread.priority
    # Jump into next thread
    _riot_context_restore(uc, cur_riot_thread)


def thread_create(uc):
    global riot_threads
    # kernel_pid_t __cdecl thread_create(unsigned __int8 *stack, int stacksize, unsigned __int8 priority, int flags, thread_task_func_t function, void *arg, const unsigned __int8 *name)
    # Add a thread to the thread list
    thr = RiotThread()
    thr.stack = uc.reg_read(UC_ARM_REG_R0)
    assert(thr.stack != 0)
    thr.stack_len = uc.reg_read(UC_ARM_REG_R1)
    assert (thr.stack_len != 0)
    thr.priority = uc.reg_read(UC_ARM_REG_R2)
    assert (thr.priority <= 255)
    thr.func = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP), 4))[0]
    assert (thr.func != 0)
    thr.arg = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP) + 0x4, 4))[0]
    name_ptr = struct.unpack("<I", uc.mem_read(uc.reg_read(UC_ARM_REG_SP) + 0x8, 4))[0]
    assert(name_ptr != 0)
    s = b''
    ch = uc.mem_read(name_ptr, 1)
    while ch != b'\x00':
        s += ch
        name_ptr += 1
        ch = uc.mem_read(name_ptr, 1)
    s += ch
    s = s.decode('latin1')
    thr.name = s
    print("RIOT: Creating thread %s(%#08x), stack %#08x[%#08x], priority %d" % (thr.name, thr.func, thr.stack, thr.stack_len, thr.priority))
    thr.context[13] = thr.stack # Set thread SP
    thr.context[14] = uc.symbols['sched_task_exit'] # Set thread LR; we need this for when threads exit
    thr.context[15] = thr.func # Set thread PC
    riot_threads.append(thr)
    pid = riot_threads.index(thr)
    uc.reg_write(UC_ARM_REG_R0, pid)


def sched_task_exit(uc):
    global cur_riot_thread
    print("RIOT: Task %s exiting" % (cur_riot_thread.name))
    cur_riot_thread = None
    riot_sched(uc)


def cpu_switch_context_exit(uc):
    # Start the scheduler
    print("RIOT: Running scheduler")
    riot_sched(uc)

def thread_measure_stack_free(uc):
    uc.reg_write(UC_ARM_REG_R0), 0x4000)
