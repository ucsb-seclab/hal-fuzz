#ifndef NATIVE_HOOKS_H
#define NATIVE_HOOKS_H

#include "unicorn/unicorn.h"

//#define DEBUG
// #define USE_BITOPTS

typedef void (*exit_hook_t)(int, int);
typedef void (*mmio_region_added_cb_t)(uint64_t, uint64_t);

void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void do_exit(int status, int sig);
uc_err load_fuzz(const char *path);
void get_fuzz(char *buf, unsigned int size);

/**
 * Version handing out a pointer into the fuzz input buffer instead of copying contents.
 * One use case for this is to avoid excessive copying on the c->python boundary.
 **/
char *get_fuzz_ptr(uint32_t size);

uint32_t fuzz_remaining();
uc_err init(uc_engine *uc, int fuzz_mmio, exit_hook_t p_exit_hook, mmio_region_added_cb_t p_mmio_region_added_cb, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, void *p_py_default_mmio_user_data, int max_num_dynamically_added_mmio_pages, uint32_t num_exit_at_bbls, uint64_t *exit_at_bbls, uint32_t num_allowed_irq_numbers, uint8_t *allowed_irq_numbers);
uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end);
uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback, uint64_t start, uint64_t end, uint32_t pc, void *user_data);
uc_err add_unmapped_mem_hook(uc_engine *uc);
uc_err register_py_handled_mmio_ranges(uc_engine *uc, uc_cb_hookmem_t py_callback, uint64_t *starts, uint64_t *ends, int num_ranges);
uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *init_vals, uint32_t *steps, int num_ranges);
uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *vals, int num_ranges);
uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint8_t *byte_sizes, uint8_t *left_shifts, uint32_t *masks, int num_ranges);
uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *value_nums, uint32_t **value_lists, int num_ranges);
uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs, int num_addresses);
uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address);
uc_err register_cond_py_handler_hook(uc_engine *uc, uc_cb_hookcode_t py_callback, uint64_t *addrs, int num_addrs, void *user_data);

#endif
