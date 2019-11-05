#ifndef NATIVE_TIMER_H
#define NATIVE_TIMER_H

#include <unicorn/unicorn.h>
typedef void (*timer_cb)(uc_engine *uc, uint32_t id, void *user_data);

struct Timer
{
    int64_t ticker_val;
    int64_t reload_val;
    timer_cb trigger_callback;
    void *trigger_cb_user_data;
    uint32_t irq_num;
    uint8_t in_use;
    uint8_t is_active;
};

uc_err init_timer_hook(uc_engine *uc, uint32_t global_timer_scale);
uint32_t add_timer(int64_t reload_val, void *trigger_callback, void *user_data, uint32_t isr_num);
uc_err rem_timer(uint32_t id);
uc_err reset_timer(uint32_t id);
uc_err start_timer(uint32_t id);
uc_err stop_timer(uint32_t id);
uint32_t is_running(uint32_t id);

#endif