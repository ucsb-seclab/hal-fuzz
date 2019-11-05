from unicorn import *
from unicorn.arm_const import *
import struct
from . import globs
from .handlers import add_block_hook
from .exit import do_exit

# Some Cortex M3 specific constants
EXCEPT_MAGIC_RET_MASK = 0xfffffff0
NVIC_MMIO_BASE = 0xE000E100
NVIC_MMIO_END = 0xE000E4EF
VTOR_BASE = 0xE000ED08
CPSR_F = 1 << 6
CPSR_I = 1 << 7
PTR_SIZE = 4

"""
NOW OBSOLETE. Kept around for reference as this is the first working
version which got now ported into the native library (see ../native/nvic.c).

Basic interrupt controller implementation which is expected to
work with unicorn hooks. This is a POC and misses a lot of features
such as:
- Banked Registers
- Priorities
- Nested (derived) exceptions

Handling of VTOR is done by mapping the vtor mmio address and listening
for writes to the vtor register. Upon invocation of an interrupt, the handler
is read from the given address in running state memory.
"""

def nvic_tick_hook(uc, address, size, user_data):
    NVIC.handle_tick()


def handler_vtor_write(uc, mem_type, address, size, value, user_data):
    if address == VTOR_BASE:
        if globs.debug_enabled:
            print(
                "############################################# Changing nvic vtor to 0x{:08x}".format(value))
        NVIC.set_vtor(value)


def handler_mmio_write(uc, mem_type, address, size, value, user_data):
    NVIC.handle_mmio_write(address, size, value)


def handler_mmio_read(uc, mem_type, address, size, value, user_data):
    NVIC.handle_mmio_read(address, size)


def nvic_exit_hook(uc, address, size, user_data):
    do_exit(0)


class VecInfo:
    def __init__(self, prio=0, enabled=True, level=0, pending=False, active=False):
        self.prio = prio
        self.enabled = enabled
        self.level = level
        self.pending = pending
        self.active = active


class NVIC():
    FRAME_SIZE = 0x20
    vectors = []

    @classmethod
    def configure(cls, uc, num_vecs=128, initial_vtor=0):
        cls.little_endian = (uc.query(UC_QUERY_MODE) & UC_MODE_BIG_ENDIAN) == 0
        cls.uc = uc
        cls.curr_active = -1
        cls.pack_prefix = "<" if cls.little_endian else ">"
        cls.vtor = initial_vtor
        cls.pending = []

        """if 'memory_map' in config:
            if 'ivt' in config['memory_map']:
                cls.vtor = config['memory_map']['ivt']['base_addr']
        """

        # TODO: vector 0 and immutable priorities for internal interrupts
        cls.vectors = [VecInfo() for _ in range(num_vecs)]

        add_block_hook(nvic_tick_hook)

        # Listen for changes to vtor base address
        uc.hook_add(UC_HOOK_MEM_WRITE, handler_vtor_write,
                    user_data=None, begin=VTOR_BASE, end=VTOR_BASE)
            
            # TODO: mmio handling not yet implemented
            #uc.hook_add(UC_HOOK_MEM_READ, handler_mmio_read,
            #            user_data=None, begin=NVIC_MMIO_BASE, end=NVIC_MMIO_END)
            #uc.hook_add(UC_HOOK_MEM_WRITE, handler_mmio_write,
            #            user_data=None, begin=NVIC_MMIO_BASE, end=NVIC_MMIO_END)
        #else:
            # if the nvic is not enabled, set special one-time handler to exit
        #    uc.hook_add(UC_HOOK_BLOCK, nvic_exit_hook, None, 0xffffffff & EXCEPT_MAGIC_RET_MASK, 0xffffffff)


    @classmethod
    def _push_state(cls):
        uc = cls.uc
        sp = uc.reg_read(arm_const.UC_ARM_REG_SP)
        frameptralign = (sp & 4) >> 2
        frameptr = (sp - cls.FRAME_SIZE) & ((~0b100) & 0xffffffff)

        # Could do reg_read_batch here if that was exposed in bindings
        r0 = uc.reg_read(arm_const.UC_ARM_REG_R0)
        r1 = uc.reg_read(arm_const.UC_ARM_REG_R1)
        r2 = uc.reg_read(arm_const.UC_ARM_REG_R2)
        r3 = uc.reg_read(arm_const.UC_ARM_REG_R3)

        r12 = uc.reg_read(arm_const.UC_ARM_REG_R12)
        lr = uc.reg_read(arm_const.UC_ARM_REG_LR)
        pc = uc.reg_read(arm_const.UC_ARM_REG_PC)  # retaddr

        xpsr = uc.reg_read(arm_const.UC_ARM_REG_XPSR)
        retspr = xpsr | (frameptralign << 9)
        retaddr = pc  # for now this holds as we do not care about recovering from hard faults or handling svcs

        frame = struct.pack(cls.pack_prefix + 8 * "I", r0,
                            r1, r2, r3, r12, lr, retaddr, retspr)
        uc.mem_write(frameptr, frame)

        # Adjust stack pointer
        uc.reg_write(arm_const.UC_ARM_REG_SP, frameptr)

    @classmethod
    def _enter_exception(cls, num):
        """
        Entering an exception is done when the NVIC chose
        an exception of the highest priority to be serviced
        """
        assert (cls.curr_active == -1)

        vector = cls.vectors[num]
        vector.pending = False
        vector.active = True
        cls.curr_active = num
        cls._push_state()
        isr, = struct.unpack(cls.pack_prefix+"I",
                             cls.uc.mem_read(cls.vtor+num * 4, 4))

        if globs.debug_enabled:
            print("Redirecting irq {} to isr: 0x{:08x}".format(num, isr))
        cls.uc.reg_write(arm_const.UC_ARM_REG_LR, EXCEPT_MAGIC_RET_MASK)
        cls.uc.reg_write(arm_const.UC_ARM_REG_PC, isr)

    @classmethod
    def _pop_state(cls):
        uc = cls.uc
        frameptr = uc.reg_read(arm_const.UC_ARM_REG_SP)
        frame_bytes = uc.mem_read(frameptr, cls.FRAME_SIZE)

        r0, r1, r2, r3, r12, lr, pc, retpsr = struct.unpack(
            cls.pack_prefix + 8 * "I", frame_bytes)

        # Align stack
        sp = uc.reg_read(arm_const.UC_ARM_REG_SP)
        sp += cls.FRAME_SIZE
        if retpsr & (1 << 9) != 0:
            sp += 4

        # Could do reg_write_batch here if that was exposed in bindings
        uc.reg_write(arm_const.UC_ARM_REG_R0, r0)
        uc.reg_write(arm_const.UC_ARM_REG_R1, r1)
        uc.reg_write(arm_const.UC_ARM_REG_R2, r2)
        uc.reg_write(arm_const.UC_ARM_REG_R3, r3)
        uc.reg_write(arm_const.UC_ARM_REG_R12, r12)

        uc.reg_write(arm_const.UC_ARM_REG_LR, lr)
        uc.reg_write(arm_const.UC_ARM_REG_PC, pc)
        uc.reg_write(arm_const.UC_ARM_REG_SP, sp)

        # For simplicity we are discarding quite a bit of state logic here
        uc.reg_write(arm_const.UC_ARM_REG_XPSR, retpsr)

    @classmethod
    def _find_pending(cls):
        """
        Find the next pending interrupt to acknowledge (activate)
        """
        if cls.pending:
            return cls.pending.pop()

        # For now just look for the first one that is actually pending (ignoring priorities)
        # for i, vector in enumerate(cls.vectors):
        #    if vector.pending:
        #        return i

        return -1

    @classmethod
    def _exit_exception(cls):
        """
        Exiting an exception happend in response to PC being
        set to an EXC_RETURN value (PC mask 0xfffffff0).
        During exception return, either the next exception has
        to be serviced (tail chaining) or the previous processor
        state (stack frame) has to be restored and user space
        operation has to be resumed.
        """
        
        if globs.debug_enabled:
            print("Exiting from exception...")
        # assert(cls.curr_active != -1)
        cls._pop_state()
        cls.vectors[cls.curr_active].active = False
        cls.curr_active = -1

    @staticmethod
    def _is_exception_ret(pc):
        """
        Detect returns from an ISR by the PC value
        """
        return pc & EXCEPT_MAGIC_RET_MASK == EXCEPT_MAGIC_RET_MASK

    @classmethod
    def _interrupts_enabled(cls):
        cpsr = cls.uc.reg_read(UC_ARM_REG_CPSR)

        # TODO: CPSR_F seems to be always set by qemu which means interrupts are always disabled?
        # TODO: CPSR_I (PRIMASK register) normally uses BASEPRI to set a minimum priority for interrupts to be activated
        res = cpsr & (CPSR_I) == 0  # cpsr & (CPSR_I | CPSR_F) == 0

        return res

    @classmethod
    def set_pending(cls, num):
        cls.pending.append(num)
        cls.vectors[num].pending = True

    @classmethod
    def enable(cls, num):
        # TODO: deal with irq 0
        cls.vectors[num].enabled = True

    @classmethod
    def disable(cls, num):
        # TODO: deal with irq 0 or others being disabled if it becomes neccessary
        cls.vectors[num].enabled = False

    @classmethod
    def set_vtor(cls, addr):
        cls.vtor = addr

    @classmethod
    def write_irq_handler(cls, num, handler_addr):
        if globs.debug_enabled:
            print("Setting irq handler nr {} to 0x{:08x}, vtor currently at: 0x{:08x}".format(
                num, handler_addr, cls.vtor))
        return cls.uc.mem_write(cls.vtor+PTR_SIZE*num, struct.pack(cls.pack_prefix+"I", handler_addr))

    @classmethod
    def handle_tick(cls):
        uc = cls.uc
        curr_pc = uc.reg_read(arm_const.UC_ARM_REG_R15)
        if cls._is_exception_ret(curr_pc):
            if globs.debug_enabled:
                print("############## Returning from interrupt...")
            cls._exit_exception()
            return False
        elif cls.curr_active == -1 and cls._interrupts_enabled():
            ind = cls._find_pending()
            if ind != -1:
                if globs.debug_enabled:
                    print("#################### Activating pending interrupt...")
                cls._enter_exception(ind)

        return False

    @classmethod
    def handle_mmio_read(cls, address, size):
        if globs.debug_enabled:
            print("[NVIC] handling incoming mmio read of size {} from 0x{:x}".format(
                size, address))

    @classmethod
    def handle_mmio_write(cls, address, size, val):
        if globs.debug_enabled:
            print("[NVIC] handling incoming mmio write of size {} to 0x{:x} with value 0x{:x}".format(
                size, address, val))
