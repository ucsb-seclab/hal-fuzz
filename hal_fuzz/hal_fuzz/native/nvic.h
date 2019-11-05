#ifndef NATIVE_NVIC_H
#define NATIVE_NVIC_H

#include <unicorn/unicorn.h>

typedef struct VecInfo {
    /* Exception priorities can range from -3 to 255; only the unmodifiable
     * priority values for RESET, NMI and HardFault can be negative.
     */
    int16_t prio;
    uint8_t enabled;
    uint8_t pending;
    uint8_t active;
    uint8_t level; /* exceptions <=15 never set level */
} VecInfo;

typedef struct NVIC {
    uint32_t vtor;
    struct VecInfo *vectors;
    uint32_t num_vectors;
    int curr_active;
} NVIC;

extern uc_err init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_vectors, uint32_t is_oneshot);
extern void nvic_set_pending(uint32_t num);

#endif