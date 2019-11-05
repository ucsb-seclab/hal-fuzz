#ifndef INTERRUPT_TRIGGERS_H
#define INTERRUPT_TRIGGERS_H

#include <unicorn/unicorn.h>

typedef struct InterruptTrigger {
    uc_hook hook_handle;
    uint32_t irq;
    uint16_t do_fuzz;
    uint16_t skip_next;
    uint32_t times_to_skip; /* Number of times to skip the basic block before triggering? */
    // TODO: how to implement this?
    uint32_t times_to_pend; /* Number of times to pend at a time */
    uint32_t curr_skips; /* Currently already skipped */
    uint32_t curr_pends; /* Currently already pended */
} InterruptTrigger;

uc_hook add_interrupt_trigger(uc_engine *uc, uint64_t addr, uint32_t irq, uint32_t num_skips, uint32_t num_pends, uint32_t do_fuzz);

#endif