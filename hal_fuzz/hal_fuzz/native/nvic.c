#include <unicorn/unicorn.h>
#include "nvic.h"
#include "native_hooks.h"

/*
Basic interrupt controller implementation which is expected to
work with unicorn hooks. This is a POC and misses a lot of features
such as:
- Banked Registers
- Priorities
- Nested (derived) exceptions
- SVC handling (ret address needs to be fixed up in that case)
- Differing endianness between host and emulated code
- Tail chaining
- Checking if interrupts are enabled
- NVIC MMIO interface

Handling of VTOR is done by mapping the vtor mmio address and listening
for writes to the vtor register. Upon invocation of an interrupt, the handler
is read from the given address in running state memory.
 */

// Some Cortex M3 specific constants
uint32_t EXCEPT_MAGIC_RET_MASK = 0xfffffff0;
#define NVIC_MMIO_BASE 0xE000E100
#define NVIC_MMIO_END 0xE000E4EF
#define VTOR_BASE 0xE000ED08
#define NVIC_VTOR_NONE 0xffffffff
#define CPSR_F (1 << 6)
#define CPSR_I (1 << 7)
#define PTR_SIZE 4
#define FRAME_SIZE 0x20
#define EXCEPTION_NO_INACTIVE 0xffffffff
#define MAX_NUM_VECTORS 0x100

uc_hook nvic_block_hook_handle = -1, hook_write_vtor_handle = -1;

struct NVIC nvic;

static void set_vtor(uint32_t addr);
static void nvic_tick_block_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

static void handler_vtor_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    #ifdef DEBUG
    printf("############################################# Changing nvic vtor to 0x%08lx", value);
    #endif
    set_vtor(value);
}

//static void handler_mmio_write(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
//    // TODO: implement
//}
//
//static void handler_mmio_read(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
//    // TODO: implement
//}

void nvic_exit_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    #ifdef DEBUG
    printf("Exiting on return of one-shot isr handler");
    #endif
    do_exit(0, -1);
}

static void init_vecinfo(VecInfo *vi, int16_t prio, uint8_t enabled, uint8_t pending, uint8_t active, uint8_t level){
    vi->prio = prio;
    vi->enabled = enabled;
    vi->pending = pending;
    vi->active = active;
    vi->level = level;
}

uc_err init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_vectors, uint32_t is_oneshot) {
    #ifdef DEBUG
    printf("[NVIC] init_nvic called with vtor: %x, num_vectors: %d\n", vtor, num_vectors);
    #endif

    if(num_vectors > MAX_NUM_VECTORS) {
        num_vectors = MAX_NUM_VECTORS;
    }

    // initialize vectors
    nvic.curr_active = EXCEPTION_NO_INACTIVE;
    nvic.num_vectors = num_vectors;
    nvic.vectors = calloc(num_vectors, sizeof(struct VecInfo));
    if (!nvic.vectors)
    {
        puts("[NVIC ERROR] init_nvic: Could not create vectors buffer");
        return UC_ERR_EXCEPTION;
    }
    for (uint32_t i = 0; i < num_vectors; ++i) {
        init_vecinfo(&nvic.vectors[i], 0, 1, 0, 0, 0);
    }

    // Set the vtor. If it is uninitialized, read it from actual (restored) process memory
    if(vtor == NVIC_VTOR_NONE) {
        uc_mem_read(uc, VTOR_BASE, &nvic.vtor, sizeof(nvic.vtor));
        printf("[NVIC] Recovered vtor base: %x\n", nvic.vtor);
    }
    else
    {
        nvic.vtor = vtor;
    }
    
    // 1. block hook
    if(is_oneshot) {
        uc_hook_add(uc, &nvic_block_hook_handle, UC_HOOK_BLOCK, nvic_exit_hook, NULL, EXCEPT_MAGIC_RET_MASK, EXCEPT_MAGIC_RET_MASK);
    }

    // TODO: We may want to go with a hook/unhook implementation here instead of using the unconditional one?
    uc_hook_add(uc, &nvic_block_hook_handle, UC_HOOK_BLOCK, nvic_tick_block_hook, NULL, 1, 0);
    
    // 2. write handler to vtor
    uc_hook_add(uc, &hook_write_vtor_handle, UC_HOOK_MEM_WRITE, handler_vtor_write, 0, VTOR_BASE, VTOR_BASE);
    // 3. nvic MMIO range read/write handler
    // TODO: Not currently implemented, yet

    return UC_ERR_OK;
}

#define NUM_SAVED_REGS 9
static int saved_reg_ids[NUM_SAVED_REGS] = {
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_XPSR,
    UC_ARM_REG_SP
};
static struct {
    uint32_t r0, r1, r2, r3, r12, lr, pc_retaddr, xpsr_retspr, sp;
} saved_regs;

static uint32_t *saved_reg_ptrs[NUM_SAVED_REGS] = {
    &saved_regs.r0,
    &saved_regs.r1, &saved_regs.r2,
    &saved_regs.r3, &saved_regs.r12,
    &saved_regs.lr, &saved_regs.pc_retaddr,
    &saved_regs.xpsr_retspr, &saved_regs.sp
};


static void push_state(uc_engine *uc)
{
    // Could do reg_read_batch here if that was exposed in bindings
    if(uc_reg_read_batch(uc, &saved_reg_ids[0], (void **)(&saved_reg_ptrs[0]), NUM_SAVED_REGS) != UC_ERR_OK) {
        perror("[NVIC ERROR] push_state: Failed reading registers\n");
        exit(-1);
    }

    uint32_t frameptralign = (saved_regs.sp & 4) >> 2;
    uint32_t frameptr;
    frameptr = (saved_regs.sp - FRAME_SIZE) & ((~0b100) & 0xffffffff);

    // TODO: for now this holds as we do not care about recovering from hard faults or handling svcs
    // As soon as we support SVCs and hard fault recovery, we need to update retaddr from saved_pc like this:
    // More verbose versions:
    // 1. retaddr
    // retaddr = saved_pc;
    // saved_regs.pc_retaddr = retaddr;
    // uc.mem_write(frameptr, frame)
    // 2. retspr
    // retspr = saved_regs.xpsr_retspr | (frameptralign << 9);
    // saved_regs.xpsr_retspr = retspr;
    // frame = struct.pack(cls.pack_prefix + 8 * "I", r0,
    //                    r1, r2, r3, r12, lr, retaddr, retspr)

    // Condensed version with unmodified retaddr (which would be required for returning from hard faults and svcs)
    saved_regs.xpsr_retspr |= (frameptralign << 9);
    uc_mem_write(uc, frameptr,  &saved_regs, (NUM_SAVED_REGS - 1)*sizeof(saved_regs.r0));

    // Adjust stack pointer
    uc_reg_write(uc, UC_ARM_REG_SP, &frameptr);
}


static void enter_exception(uc_engine *uc, uint32_t num) {
    if(nvic.curr_active != EXCEPTION_NO_INACTIVE) {
        //perror("[NVIC ERROR] enter_exception: expected no other exception to be active\n");
        exit(-1);
    }

    nvic.vectors[num].pending = 0;
    nvic.vectors[num].active = 1;
    nvic.curr_active = num;
    push_state(uc);

    uint32_t isr;
    if(uc_mem_read(uc, nvic.vtor + num * 4, &isr, 4) != UC_ERR_OK) {
        perror("[NVIC ERROR] enter_exception: reading isr address failed\n");
        exit(-1);
    }

    #ifdef DEBUG
    printf("Redirecting irq %d to isr: 0x%08x\n", num, isr);
    #endif
    if((uc_reg_write(uc, UC_ARM_REG_LR, &EXCEPT_MAGIC_RET_MASK) != UC_ERR_OK) || (uc_reg_write(uc, UC_ARM_REG_PC, &isr) != UC_ERR_OK)) {
        perror("[NVIC ERROR] enter_exception: setting LR or setting isr address failed\n");
        exit(-1);
    }
}

static void pop_state(uc_engine *uc) {
    uint32_t frameptr;
    uc_reg_read(uc, UC_ARM_REG_SP, &frameptr);
    // We use a bytemagic shortcut here. This heavily relies on the correct size of saved_regs vs. FRAME_SIZE
    // char frame_bytes[FRAME_SIZE];
    // r0, r1, r2, r3, r12, lr, pc, retpsr = struct.unpack(cls.pack_prefix + 8 * "I", frame_bytes)

    if(uc_mem_read(uc, frameptr, &saved_regs, FRAME_SIZE) != UC_ERR_OK) {
        perror("[NVIC ERROR] pop_state: reading saved context frame failed\n");
        exit(-1);
    }

    // Align stack
    uc_reg_read(uc, UC_ARM_REG_SP, &saved_regs.sp);
    saved_regs.sp += FRAME_SIZE;
    if ((saved_regs.xpsr_retspr & (1 << 9)) != 0)
    {
        saved_regs.sp += 4;
    }

    // Doing reg_write_batch here if instead of the one-reg-at-a-time approach from the python implementation
    /* 
    uc.reg_write(arm_const.UC_ARM_REG_R0, r0) 
    uc.reg_write(arm_const.UC_ARM_REG_R1, r1) 
    uc.reg_write(arm_const.UC_ARM_REG_R2, r2)
    uc.reg_write(arm_const.UC_ARM_REG_R3, r3)
    uc.reg_write(arm_const.UC_ARM_REG_R12, r12)
    uc.reg_write(arm_const.UC_ARM_REG_LR, lr)
    uc.reg_write(arm_const.UC_ARM_REG_PC, pc)
    uc.reg_write(arm_const.UC_ARM_REG_SP, sp)

    // TODO: for simplicity we are discarding quite a bit of state logic here
    uc.reg_write(arm_const.UC_ARM_REG_XPSR, retpsr)
    */
    
    // Here we restore all registers in one go, including sp
    if(uc_reg_write_batch(uc, &saved_reg_ids[0], (void **)(&saved_reg_ptrs[0]), NUM_SAVED_REGS)!=UC_ERR_OK){
        perror("[NVIC ERROR] pop_state: restoring registers failed\n");
        exit(-1);
    }
}

static int32_t find_pending() {
    /* Find the next pending interrupt to acknowledge (activate). If none are active, -1 is returned */

    // For now just look for the first one that is actually pending (ignoring priorities)
    for(int32_t i = 1; i < nvic.num_vectors; ++i) {
        if (nvic.vectors[i].pending)
            return i;
    }

    return -1;
}

static void exit_exception(uc_engine *uc) {
    /*
        Exiting an exception happens in response to PC being
        set to an EXC_RETURN value (PC mask 0xfffffff0).
        During exception return, either the next exception has
        to be serviced (tail chaining) or the previous processor
        state (stack frame) has to be restored and user space
        operation has to be resumed.
    */
    #ifdef DEBUG
    puts("Exiting from exception...");
    #endif

    if(nvic.curr_active == EXCEPTION_NO_INACTIVE) {
        puts("[NVIC ERROR] exit_exception: Inconsistent state: no exception is active");
        exit(-1);
    }
    pop_state(uc);

    // TODO: implement tail chaining
    nvic.vectors[nvic.curr_active].active = 0;
    nvic.curr_active = EXCEPTION_NO_INACTIVE;
}

#define is_exception_ret(pc) ((pc & EXCEPT_MAGIC_RET_MASK) == EXCEPT_MAGIC_RET_MASK)

static inline int interrupts_enabled(uc_engine *uc) {
    uint32_t cpsr;
    uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);

    // TODO: CPSR_F seems to be always set by qemu which means interrupts are always disabled?
    // TODO: CPSR_I (PRIMASK register) normally uses BASEPRI to set a minimum priority for interrupts to be activated
    return (cpsr & CPSR_I) == 0; // # cpsr & (CPSR_I | CPSR_F) == 0
}

void nvic_set_pending(uint32_t num) {
    #ifdef DEBUG
    printf("[NVIC] nvic_set_pending: vector no: %d\n", num);
    #endif
    if(num > nvic.num_vectors) {
        perror("[NVIC ERROR] nvic_set_pending: too high interrupt number specified!\n");
        exit(-1);
    }
    nvic.vectors[num].pending = 1;
}

void nvic_enable(int num) {
    nvic.vectors[num].enabled = 1;
}

void nvic_enter_exception(uc_engine *uc, int num) {
    enter_exception(uc, num);
}

void nvic_disable_vector(int num) {
    nvic.vectors[num].enabled = 0;
}

static void set_vtor(uint32_t addr) {
    nvic.vtor = addr;
}

void nvic_write_irq_handler(uc_engine *uc, int num, uint32_t handler_addr) {
    #ifdef DEBUG
    printf("Setting irq handler nr %d to 0x%08x, vtor currently at: 0x%08x", num, handler_addr, nvic.vtor);
    #endif

    if(uc_mem_write(uc, nvic.vtor+PTR_SIZE*num, &handler_addr, PTR_SIZE) != UC_ERR_OK) {
        perror("[NVIC ERROR] write_irq_handler: Could not write handler to vector table\n");
        exit(-1);
    }
}

static void nvic_tick_block_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    if(is_exception_ret(address)) {
        #ifdef DEBUG
        printf("#################### Returning from interrupt (addr: 0x%lx)...\n", address);
        #endif
        exit_exception(uc);
        #ifdef DEBUG
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("############## Returned from interrupt. From: 0x%08lx to 0x%08x\n", address, pc);
        #endif
    } else if (nvic.curr_active == EXCEPTION_NO_INACTIVE) { //&& interrupts_enabled(uc)) { // TODO: FIX this
        int ind = find_pending();

        if(ind != -1) {
            #ifdef DEBUG
            puts("#################### Activating pending interrupt...");
            #endif
            enter_exception(uc, ind);
            #ifdef DEBUG
            uint32_t pc;
            uc_reg_read(uc, UC_ARM_REG_PC, &pc);
            printf("#################### Activated pending interrupt. From: 0x%08lx to 0x%08x\n", address, pc);
            #endif
        }
    }
}