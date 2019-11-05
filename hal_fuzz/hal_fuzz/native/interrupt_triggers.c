#include "interrupt_triggers.h"
#include "native_hooks.h"
#include "nvic.h"

#define MAX_INTERRUPT_TRIGGERS 256

static int num_triggers_inuse = 0;
static InterruptTrigger triggers[MAX_INTERRUPT_TRIGGERS];

static void interrupt_trigger_tick_block_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    InterruptTrigger *trigger = (InterruptTrigger *) user_data;

    #ifdef DEBUG
    printf("[INTERRUPT TRIGGER] Trigger callback called at address 0x%lx\n", address);
    #endif

    if(trigger->skip_next) {
        // We are coming from where we triggered the interrupt
        trigger->skip_next = 0;
        return;
    } else if (trigger->curr_pends)
    {
        // Already on the pending train, follow it
        nvic_set_pending(trigger->irq);
        ++trigger->curr_pends;
        #ifdef DEBUG
        printf("[INTERRUPT TRIGGER] On pending train: %d/%d\n", trigger->curr_pends, trigger->times_to_pend);
        #endif
    } else if(trigger->curr_skips < trigger->times_to_skip) {
        // We need to wait for a bit longer
        ++trigger->curr_skips;
        #ifdef DEBUG
        printf("[INTERRUPT TRIGGER] Trigger skipping %d/%d\n", trigger->curr_skips, trigger->times_to_skip);
        #endif
    } else {
        // Waiting is over, check whether to do anything
        if (!trigger->do_fuzz)
        {
            #ifdef DEBUG
            printf("[INTERRUPT TRIGGER] Pending interrupt automatically: %d\n", trigger->irq);
            #endif
            // Pend in all cases
            nvic_set_pending(trigger->irq);
            ++trigger->curr_pends;
        }
        else
        {
            // Only pend if fuzzer decides to do so
            uint8_t fuzzer_byte, hw;
            get_fuzz((void *)&fuzzer_byte, sizeof(fuzzer_byte));

            // Base the decision on the number of 1-bits in the fuzzer byte to broaden effects of changes
            for (; fuzzer_byte; fuzzer_byte>>=1) {
                if(fuzzer_byte & 1) {
                    ++hw;
                }
            }
            
            if (hw & 1)
            {
                #ifdef DEBUG
                printf("[INTERRUPT TRIGGER] Pending interrupt from by fuzzer choice: %d\n", trigger->irq);
                #endif
                nvic_set_pending(trigger->irq);
                ++trigger->curr_pends;
            }
            #ifdef DEBUG
            else {
                printf("[INTERRUPT TRIGGER] Fuzzer elected not to trigger interrupt: %d\n", trigger->irq);
            }
            #endif
        }
    }

    if (trigger->curr_pends == trigger->times_to_pend)
    {
        trigger->curr_pends = 0;
        trigger->curr_skips = 0;
        trigger->skip_next = 1;

        #ifdef DEBUG
        printf("[INTERRUPT TRIGGER] Resetting interrupt curr_pends and skips\n");
        #endif
    }
}

uc_hook add_interrupt_trigger(uc_engine *uc, uint64_t addr, uint32_t irq, uint32_t num_skips, uint32_t num_pends, uint32_t do_fuzz) {
    if(num_triggers_inuse >= MAX_INTERRUPT_TRIGGERS) {
        perror("[INTERRUPT_TRIGGERS ERROR] register_interrupt_trigger: Maxmimum number of interrupt triggers exhausted.\n");
        exit(-1);
    }

    /* if(num_pends != 1) {
        perror("[INTERRUPT_TRIGGERS ERROR] register_interrupt_trigger: Pending more than once on interrupt trigger is currently not supported\n");
        exit(-1);
    }*/

    InterruptTrigger *trigger = &triggers[num_triggers_inuse++];
    if (uc_hook_add(uc, &trigger->hook_handle, UC_HOOK_BLOCK, (void *)interrupt_trigger_tick_block_hook, trigger, addr, addr) != UC_ERR_OK)
    {
        perror("[INTERRUPT_TRIGGERS ERROR] Failed adding block hook.\n");
        exit(-1);
    }

    trigger->irq = irq;
    trigger->curr_pends = 0;
    trigger->curr_skips = 0;
    trigger->times_to_pend = num_pends;
    trigger->times_to_skip = num_skips;
    trigger->do_fuzz = do_fuzz;    

    return UC_ERR_OK;
}