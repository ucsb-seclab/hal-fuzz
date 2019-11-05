#include <unicorn/unicorn.h>
#include "timer.h"
#include <string.h>
#include "native_hooks.h"
#include "nvic.h"

#define MAX_TIMERS 32
#define IRQ_NOT_USED 0xffffffff
#define DEFAULT_GLOBAL_TIMER_SCALE 1

uc_hook timer_block_hook_handle;

/*
    We use an array of timers with an in_use flag for every timer.
    We keep track of the number of indices touched so far (end_ind)
    as well as the number of currently used timers (in_use).
    
    When adding a timer, we either use the next unused timer or re-use
    previously used and then released timer slots.
 */
uint32_t timer_scale = DEFAULT_GLOBAL_TIMER_SCALE;
uint32_t end_ind = 0;
uint32_t in_use = 0;
struct Timer timers[MAX_TIMERS];

uint32_t add_timer(int64_t reload_val, void *trigger_callback, void *trigger_cb_user_data, uint32_t isr_num) {
    if(in_use == MAX_TIMERS) {
        perror("[TIMER ERROR] add_timer: Maximum number of timers is already used\n");
        exit(-1);
    }
    if(trigger_callback == NULL && isr_num == IRQ_NOT_USED) {
        perror("[TIMER ERROR] add_timer: No callback or irq passed to newly created timer\n");
        exit(-1);
    }

    uint32_t ind;
    if (in_use == end_ind)
    {
        // Insert new at the end
        ind = end_ind++;
    }
    else
    {
        // Find a gap
        for (ind = 0; ind < end_ind; ++ind) {
            if(timers[ind].in_use) {
                break;
            }
        }
    }
    ++in_use;

    timers[ind].in_use = 1;
    timers[ind].irq_num = isr_num;
    timers[ind].ticker_val = reload_val;
    timers[ind].reload_val = reload_val;
    timers[ind].trigger_callback = trigger_callback;
    timers[ind].trigger_cb_user_data = trigger_cb_user_data;
    timers[ind].is_active = 1;
    
    return ind;
}

uc_err rem_timer(uint32_t id) {
    // Catch bugs from the other side
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] rem_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers[id].in_use) {
        perror("[TIMER ERROR] rem_timer: Unused timer to be removed\n");
        exit(-1);
    }

    memset(&timers[id], 0, sizeof(struct Timer));
    // Delete tail entries if we can
    while(id != -1 && id == end_ind-1) {
        if(timers[id].in_use) {
            break;
        } else {
            --id;
            --end_ind;
        }
    }
    --in_use;

    return UC_ERR_OK;
}

uc_err reset_timer(uint32_t id) {
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] reset_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers[id].in_use) {
        perror("[TIMER ERROR] reset_timer: Unused timer to be reset\n");
        exit(-1);
    }

    timers[id].ticker_val = timers[id].reload_val;

    return UC_ERR_OK;
}

uc_err start_timer(uint32_t id) {
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] start_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers[id].in_use) {
        perror("[TIMER ERROR] start_timer: Unused timer to be started\n");
        exit(-1);
    }

    timers[id].is_active = 1;

    return UC_ERR_OK;
}

uint32_t is_running(uint32_t id) {
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] start_timer: Too high id passed\n");
        exit(-1);
    }
    return timers[id].is_active;
}


uc_err stop_timer(uint32_t id) {
    if(id >= MAX_TIMERS) {
        perror("[TIMER ERROR] stop_timer: Too high id passed\n");
        exit(-1);
    } else if(!timers[id].in_use) {
        perror("[TIMER ERROR] stop_timer: Unused timer to be started\n");
        exit(-1);
    }

    timers[id].is_active = 0;

    return UC_ERR_OK;
}

uint64_t global_ticker = 0;

uint64_t get_global_ticker() {
    return global_ticker;
}

static void timer_tick_block_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    global_ticker += timer_scale;
    for (uint32_t i = 0; i < end_ind; ++i) {
        if(!(timers[i].is_active && timers[i].in_use)) {
            continue;
        }

        timers[i].ticker_val -= timer_scale;
        if (timers[i].ticker_val < 0)
        {
            // Ding!
            #ifdef DEBUG
            printf("[TIMER] Ding! Timer %d is going off\n", i);
            #endif

            timers[i].ticker_val = timers[i].reload_val;

            if(timers[i].irq_num != IRQ_NOT_USED) {
                // pend interrupt
                #ifdef DEBUG
                printf("[TIMER] Pending irq %d\n", timers[i].irq_num);
                #endif
                nvic_set_pending(timers[i].irq_num);
            }
            if(timers[i].trigger_callback != NULL) {
                // call timer callback
                #ifdef DEBUG
                printf("[TIMER] Calling timer callback at %p\n", timers[i].trigger_callback);
                #endif
                timers[i].trigger_callback(uc, i, timers[i].trigger_cb_user_data);
            }
        }
    }
}



uc_err init_timer_hook(uc_engine *uc, uint32_t global_timer_scale) {
    // Reset timer structs
    memset(&timers[0], 0, MAX_TIMERS * sizeof(struct Timer));

    timer_scale = global_timer_scale;

    if(uc_hook_add(uc, &timer_block_hook_handle, UC_HOOK_BLOCK, (void *) timer_tick_block_hook, NULL, 1, 0) != UC_ERR_OK) {
        perror("[TIMER ERROR] init_timer_hook: Could not add timer block hook\n");
        exit(-1);
    }

    return UC_ERR_OK;
}