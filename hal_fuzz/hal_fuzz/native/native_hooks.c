/* Low level hal-fuzz hooks implemented natively for performance reasons */

#include "native_hooks.h"
#include "util.h"
#include "nvic.h"

#include <unicorn/unicorn.h>

#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/time.h>

const char FUZZER_INJECTED_INTERRUPT_TOKEN[3] = {0xFE, 0xED, 0xA0};
uint8_t allow_fuzzer_injected_interrupts = 0;
uint8_t allowed_fuzzed_irqs[256] = { 0 };

uc_hook block_hook_handle = 0;
uc_hook code_hook_handle = 0;

// ~1 MB of preallocated fuzzing buffer size
#define PREALLOCED_FUZZ_BUF_SIZE 1000000
#define MMIO_HOOK_PC_ALL_ACCESS_SITES (0xffffffffuL)

char *fuzz = (char *) 0;
char *fuzz_scratch_buf = (char *) 0;
unsigned long fuzz_size = 0;
unsigned long fuzz_cursor = 0;


#define DEFAULT_MAX_EXTRA_PAGES 32
int max_extra_pages = DEFAULT_MAX_EXTRA_PAGES;

exit_hook_t exit_hook = (exit_hook_t) 0;
mmio_region_added_cb_t mmio_region_added_cb = (mmio_region_added_cb_t)0;

uc_hook hook_block_cond_py_handlers_handle;
uc_cb_hookcode_t py_hle_handler_hook = (uc_cb_hookcode_t)0;
int num_handlers = 0;
uint64_t *bb_handler_locs = 0;

void *py_default_mmio_user_data = NULL;

#define MMIO_START_UNINIT (0xffffffffffffffffLL)
uint32_t num_mmio_regions = 0;
uint64_t *mmio_region_starts = 0;
uint64_t *mmio_region_ends = 0;

#define MAX_MMIO_CALLBACKS 4096
int num_mmio_callbacks = 0;
struct mmio_callback *mmio_callbacks[MAX_MMIO_CALLBACKS];

struct linear_mmio_model_config {
    uint32_t step;
    uint32_t val;
};

struct constant_mmio_model_config {
    uint32_t val;
};

struct bitextract_mmio_model_config {
    uint8_t byte_size;
    uint8_t left_shift;
    uint8_t mask_hamming_weight;
    uint32_t mask;
};

struct value_set_mmio_model_config {
    uint32_t num_vals;
    uint32_t *values;
};

struct mmio_callback
{
    uint64_t start;
    uint64_t end;
    uint32_t pc;
    void *user_data;
    uc_cb_hookmem_t callback;
};

#define MAX_IGNORED_ADDRESSES 4096
int num_ignored_addresses = 0;
uint64_t ignored_addresses[MAX_IGNORED_ADDRESSES];
uint32_t ignored_address_pcs[MAX_IGNORED_ADDRESSES];

void do_exit(int status, int sig){
    if(exit_hook) {
        puts("Calling exit_hook");
        exit_hook(status, sig);
    }
    else
    {
        puts("Defaulting to exit(0)");
        exit(status);
    }
}

void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic blooooock at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf("Hit exit basic block address: %08lx\n", address);
    // Status 5 signifies that we exited at the provided basic block
    do_exit(5, -1);
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

char *find_interrupt_trigger(uint32_t req_fuzz_size){
    int remaining_fuzz_size = fuzz_size - fuzz_cursor;
    int haystack_size = min(remaining_fuzz_size, req_fuzz_size + sizeof(FUZZER_INJECTED_INTERRUPT_TOKEN) - 1);

    char *res = memmem(&fuzz[fuzz_cursor], haystack_size, FUZZER_INJECTED_INTERRUPT_TOKEN, sizeof(FUZZER_INJECTED_INTERRUPT_TOKEN));

    return res;
}

void get_fuzz(char *buf, uint32_t size) {
    const char *trigger_start;
    while (allow_fuzzer_injected_interrupts && (trigger_start = find_interrupt_trigger(size)))
    {
        // First figure out how many bytes we skipped
        uint32_t skipped_bytes = trigger_start - &fuzz[fuzz_cursor];

        // Copy partial fuzzing bytes
        memcpy(buf, &fuzz[fuzz_cursor], skipped_bytes);

        // Update cursor and remaining required size
        size -= skipped_bytes;
        fuzz_cursor += skipped_bytes + (sizeof(FUZZER_INJECTED_INTERRUPT_TOKEN) + 1);

        // Deal with the interrupt
        // The irq is denominated by the byte following the interrupt token
        uint8_t chosen_irq = trigger_start[sizeof(FUZZER_INJECTED_INTERRUPT_TOKEN)];

        #ifdef DEBUG
        printf("[NATIVE FUZZ] ########################### get_fuzz: Found an interrupt token %ld bytes into the input cursor. Chosen irq: %d\n", trigger_start - fuzz, chosen_irq);
        #endif

        // Now see whether we actually want to let the irq happen or if the fuzzer mutated its own token
        if (allowed_fuzzed_irqs[chosen_irq]) {
            #ifdef DEBUG
            printf("[NATIVE FUZZ] get_fuzz: Pending irq: %d\n", chosen_irq);
            #endif
            nvic_set_pending(chosen_irq);
        } else {
            #ifdef DEBUG
            printf("[NATIVE FUZZ] get_fuzz: Discarding fuzzer-generated irq: %d\n", chosen_irq);
            #endif
        }
    }

    // Deal with copying over the (remaining) fuzzing bytes
    if(size && fuzz_cursor+size <= fuzz_size) {
        #ifdef DEBUG
        printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size);
        #endif
        memcpy(buf, &fuzz[fuzz_cursor], size);
        fuzz_cursor += size;
    } else {
        printf("\n>>> Ran out of fuzz (fuzz size: %ld)\n", fuzz_size);

        do_exit(0, -1);
    }
}

char *get_fuzz_ptr(uint32_t size) {
    // In the case where we allow tokens and hit one, default to using the scratch buffer
    if(allow_fuzzer_injected_interrupts && (find_interrupt_trigger(size) != NULL)) {
        get_fuzz(fuzz_scratch_buf, size);
        return fuzz_scratch_buf;
    }

    if(size && fuzz_cursor+size <= fuzz_size) {
        #ifdef DEBUG
        printf("[NATIVE FUZZ] Returning %d fuzz bytes\n", size);
        #endif
        char *res = &fuzz[fuzz_cursor];
        fuzz_cursor += size;
        return res;
    }
    else
    {
        printf("\n>>> Ran out of fuzz (fuzz size: %ld)\n", fuzz_size);
        do_exit(0, -1);
        return NULL;
    }
}

uint32_t fuzz_remaining() {
    return fuzz_size - fuzz_cursor;
}

uint64_t total_delta = 0;
void hook_mmio_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data)
{
    int done = 0;
    uint32_t pc = 0;
    //struct timeval tv1, tv2;
    //gettimeofday(&tv1,NULL);

    uc_reg_read(uc, UC_ARM_REG_PC, &pc);

    // TODO: optimize this lookup
    for (int i = 0; i < num_ignored_addresses; ++i)
    {
        if(addr == ignored_addresses[i] && (ignored_address_pcs[i] == MMIO_HOOK_PC_ALL_ACCESS_SITES || ignored_address_pcs[i] == pc)) {
            #ifdef DEBUG
            printf("Hit passthrough address 0x%08lx - pc: 0x%08x - returning\n", addr, pc);
            #endif
            return;
        }
    }

    // TODO: optimize this lookup
    for (int i = 0; i < num_mmio_callbacks; ++i) {
        if (addr >= mmio_callbacks[i]->start && addr <= mmio_callbacks[i]->end &&
                (mmio_callbacks[i]->pc == MMIO_HOOK_PC_ALL_ACCESS_SITES || mmio_callbacks[i]->pc == pc))
        {
            if(mmio_callbacks[i]->user_data != NULL) {
                user_data = mmio_callbacks[i]->user_data;
            }

            mmio_callbacks[i]->callback(uc, type, addr, size, value, user_data);
            done = 1;
            break;
        }
    }

    if(!done) {
        #ifdef DEBUG
        printf("Serving %d byte(s) fuzz for mmio access to 0x%08lx, pc: 0x%08x\n", size, addr, pc);
        #endif

        uint64_t val = 0;
        get_fuzz((char *)&val, size);
        #ifdef DEBUG
        printf(", value: 0x%lx\n", val);
        #endif
        uc_mem_write(uc, addr, (char *)&val, size);
    }

    //gettimeofday(&tv2,NULL);
    //uint64_t delta = 1000000LL * tv2.tv_sec + tv2.tv_usec - (1000000LL * tv1.tv_sec + tv1.tv_usec);
    //total_delta += delta;
    //printf("Number of microseconds passed: %ld, total time spent now: %ld\n", delta, total_delta);
    return;
}

uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end) {
    if(!py_default_mmio_user_data) {
        perror("ERROR. add_mmio_region: py_default_mmio_user_data is NULL (did you not register handler first?)\n");
        return UC_ERR_EXCEPTION;
    }

    uc_hook tmp;
    printf("add_mmio_region called! hooking 0x%08lx - 0x%08lx\n", begin, end);
    return uc_hook_add(uc, &tmp, UC_HOOK_MEM_READ, hook_mmio_access, py_default_mmio_user_data, begin, end);
}

int num_extra_pages = 0;
bool hook_unmapped_mem_access(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    if(num_extra_pages < max_extra_pages) {
        uint32_t pc, lr;
        uc_hook tmp;
        ++num_extra_pages;
        uint64_t page_start = address & (~0xfffL);
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        uc_reg_read(uc, UC_ARM_REG_LR, &lr);
        printf("[-] WARNING: mapping new page at 0x%08lx (0x%08lx accessed from %08x, lr: %08x)\n", page_start, address, pc, lr);
        if(uc_mem_map(uc, page_start, 0x1000, 3) != UC_ERR_OK) {
            perror("mapping file did not work...\n");
            exit(-1);
        }
        if(!py_default_mmio_user_data) {
            perror("ERROR. hook_unmapped_mem_access: py_default_mmio_user_data is NULL (did you not register handler first)\n");
            return UC_ERR_EXCEPTION;
        }

        uc_hook_add(uc, &tmp, UC_HOOK_MEM_READ, hook_mmio_access, py_default_mmio_user_data, page_start, page_start + 0x1000);

        // We notify Python of a new region being added (to add tracing handlers etc.)
        if (mmio_region_added_cb) {
            mmio_region_added_cb(page_start, page_start + 0x1000);
        }

        return true;
    }
    return false;
}

uc_err add_unmapped_mem_hook(uc_engine *uc) {
    uc_hook tmp;

    return uc_hook_add(uc, &tmp, UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_READ_INVALID, hook_unmapped_mem_access, 0, 1, 0);
}

void hook_block_cond_py_handlers(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint64_t next_val;

    // printf("C Block handler at 0x%08lx called\n", address);

    // Search for address in value list and invoke python handler if found
    for (int i = 0; i < num_handlers; ++i) {
        next_val = bb_handler_locs[i];
        if (next_val > address) {
            break;
        } else if(next_val == address) {
            py_hle_handler_hook(uc, address, size, user_data);
        }
    }
}

uc_err register_cond_py_handler_hook(uc_engine *uc, uc_cb_hookcode_t py_mmio_callback, uint64_t *addrs, int num_addrs, void *user_data) {
    py_hle_handler_hook = py_mmio_callback;
    num_handlers = num_addrs;

    bb_handler_locs = malloc(num_addrs * sizeof(uint64_t));
    if(!bb_handler_locs) {
        perror("allocating handler location struct failed\n");
        return -1;
    }

    memcpy(bb_handler_locs, addrs, num_addrs * sizeof(uint64_t));

    // shouldn't be many entries, just sort ascending this way
    for (int i = 0; i < num_addrs; i++)
	{
		for (int j = 0; j < num_addrs; j++)
		{
			if (bb_handler_locs[j] > bb_handler_locs[i])
			{
				uint64_t tmp = bb_handler_locs[i];
			    bb_handler_locs[i] = bb_handler_locs[j];
				bb_handler_locs[j] = tmp;
			}
		}
	}

    // Register unconditional hook for checking for handler presence
    return uc_hook_add(uc, &hook_block_cond_py_handlers_handle, UC_HOOK_BLOCK, hook_block_cond_py_handlers, user_data, 1, 0);
}

uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address) {
    for (int i = 0; i < num_handlers ; i++)	{
		if (bb_handler_locs[i] == address) {
            // Found the handler location, now move everything else to the front
            for(int j = i; j < num_handlers-1; ++j) {
                bb_handler_locs[j] = bb_handler_locs[j+1];
            }

            --num_handlers;
            // Now fully remove the (unconditional) hook if we can
            if(!num_handlers) {
                uc_hook_del(uc, hook_block_cond_py_handlers_handle);
            }
            return UC_ERR_OK;
        }
    }

    perror("[NATIVE ERROR] remove_function_handler_hook_address: could not find address to be removed\n");
    exit(-1);
}

uc_err register_py_handled_mmio_ranges(uc_engine *uc, uc_cb_hookmem_t py_mmio_callback, uint64_t *starts, uint64_t *ends, int num_ranges) {
    uint64_t start, end;

    if(py_default_mmio_user_data == NULL) {
        perror("ERROR. register_py_handled_mmio_ranges: python user data pointer not set up (did you forget to call init before?)\n");
        return UC_ERR_EXCEPTION;
    }

    for (int i = 0; i < num_ranges; ++i) {
        start = starts[i];
        end = ends[i];
        if(add_mmio_subregion_handler(uc, py_mmio_callback, start, end, MMIO_HOOK_PC_ALL_ACCESS_SITES, py_default_mmio_user_data) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

void linear_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct linear_mmio_model_config *model_state = (struct linear_mmio_model_config *) user_data;

    model_state->val += model_state->step;

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Linear MMIO handler: [0x%08lx] = [0x%x]\n", pc, addr, model_state->val);
    #endif

    uc_mem_write(uc, addr, &model_state->val, sizeof(model_state->val));
}

void constant_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct constant_mmio_model_config *model_state = (struct constant_mmio_model_config *) user_data;
    uint64_t val = model_state->val;

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[0x%08x] Native Constant MMIO handler: [0x%08lx] = [0x%lx]\n", pc, addr, val);
    #endif

    // TODO: This assumes shared endianness between host and target
    uc_mem_write(uc, addr, &val, size);
}

uint32_t bitextract_model_bit_pool = 0;
#ifdef USE_BITOPTS
uint32_t num_bitextract_model_bit_pool_bits = 0;
#endif
void bitextract_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data)
{
    struct bitextract_mmio_model_config *config = (struct bitextract_mmio_model_config *) user_data;
    uint64_t result_val = 0;

    if(config->byte_size >= size) {
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("ERROR bitextract_mmio_model_handler: configured byte size is greater than or equal to read size for access to %lx from %x\n", addr, pc);
        exit_hook(0, -1);
    }

    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    #ifdef USE_BITOPTS
    uint32_t prev_num_pool_bits = num_bitextract_model_bit_pool_bits;
    uint32_t prev_bit_pool = bitextract_model_bit_pool;
    #endif
    #endif


    if(config->mask_hamming_weight % 8 == 0) {
        // for a full byte read, just take new input bytes for alignment purposes
        #ifdef DEBUG
        printf("[0x%08x] Native Bitextract MMIO handler: Got byte-sized read. Serving fresh bytes\n", pc);
        #endif

        // shift fuzzer input bits into place according to mask
        uint32_t mask = config->mask;
        uint32_t tmp_bitpool = 0;
        get_fuzz((char *)(&tmp_bitpool), config->mask_hamming_weight >> 3);
        for (uint32_t i = 0; i < size * 8; ++i)
        {
            if(mask & (1<<i)) {
                result_val |= ((tmp_bitpool&1)<<i);
                tmp_bitpool >>= 1;
            }
        }
    } else {
        #ifdef USE_BITOPTS
        // unaligned number of bits
        if(num_bitextract_model_bit_pool_bits < config->mask_hamming_weight) {
            // discard any leftovers to keep locality
            get_fuzz((char *)(&bitextract_model_bit_pool), sizeof(bitextract_model_bit_pool));
            #ifdef DEBUG
            printf("[0x%08x] Native Bitextract MMIO handler: Too few bits left (%d < %d). Refilling mask to: %08x\n", pc, num_bitextract_model_bit_pool_bits, config->mask_hamming_weight, bitextract_model_bit_pool);
            #endif
            num_bitextract_model_bit_pool_bits = sizeof(bitextract_model_bit_pool)*8;
        }
        #else
            // If we don't use bits only, grab the full byte amount every time
            get_fuzz((char *)(&bitextract_model_bit_pool), (config->mask_hamming_weight >> 3)+1);
        #endif

        #ifdef DEBUG
        printf("[0x%08x] Native Bitextract MMIO handler: Building %d-bit value from input: %08x\n", pc, config->mask_hamming_weight, bitextract_model_bit_pool);
        #endif

        // shift fuzzer input bits into place according to mask
        uint32_t mask = config->mask;
        for (uint32_t i = 0; i < size * 8; ++i)
        {
            if(mask & (1<<i)) {
                result_val |= ((bitextract_model_bit_pool&1)<<i);
                bitextract_model_bit_pool >>= 1;
                #ifdef USE_BITOPTS
                --num_bitextract_model_bit_pool_bits;
                #endif
            }
        }
    }

    uc_mem_write(uc, addr, &result_val, size);

    #ifdef DEBUG
    #ifdef USE_BITOPTS
    printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] (%d byte read for mask: %08x). Bitpool now: %08x (#bits: %d). Bitpool prev %08x (#bits: %d)\n", pc, addr, result_val, size, config->mask, bitextract_model_bit_pool, num_bitextract_model_bit_pool_bits, prev_bit_pool, prev_num_pool_bits);
    #else
    printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] (%d byte read for mask: %08x, #bits: %d)\n", pc, addr, result_val, size, config->mask, config->mask_hamming_weight);
    #endif
    #endif

    /*
    uint64_t fuzzer_val = 0;
    if(size == 4 || size == 2) {

        // TODO: this currently assumes little endianness on both sides to be correct
        get_fuzz((char *)(&fuzzer_val), config->byte_size);
        result_val = fuzzer_val << config->left_shift;
        uc_mem_write(uc, addr, &result_val, size);
        #ifdef DEBUG
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("[0x%08x] Native Bitextract MMIO handler: [0x%08lx] = [0x%lx] from %d byte input: %lx\n", pc, addr, result_val, config->byte_size, fuzzer_val);
        #endif
    } else {
        // For size == 1 we should never have put a model here as it would not decrease size
        printf("ERROR bitextract_mmio_model_handler: requested size unexpectedly is not in {2, 4}\n");
        exit_hook(0, -1);
    }
    */
}

uint32_t set_model_selector_bit_pool = 0;
uint32_t num_set_model_selector_bit_pool_bits = 0;

uint8_t set_model_required_bits[] = {
    // 1 choice: 0 bits
    0,
    // 2 choices: 1 bit
    1,
    // 3 choices: 3 bits to reduce bias
    3,
    // 4 choices: 2 bits
    2,
    // 5 choices: 4 bits to reduce bias
    4,
    // 6 choices: 5 bits to reduce bias
    5,
    // 7 choices: 5 bits to reduce bias
    5,
    // 8 choices: 3 bits
    3
};

void value_set_mmio_model_handler(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data) {
    struct value_set_mmio_model_config *config = (struct value_set_mmio_model_config *) user_data;

    uint64_t result_val;
    uint8_t fuzzer_val = 0;
    #ifdef DEBUG
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    #endif

    if(config->num_vals > 1) {
        #ifdef USE_BIT_OPTS
        if(config->num_vals >= sizeof(set_model_required_bits)/sizeof(*set_model_required_bits)) {
            // too many values, use full byte
        #endif
            get_fuzz((char *)&fuzzer_val, 1);
        #ifdef USE_BIT_OPTS
        } else {
            // a low number of values, use predefined bit counts
            uint8_t required_bits = set_model_required_bits[config->num_vals-1];
            #ifdef DEBUG
            printf("[0x%08x] Native Set MMIO: small set (%d vals), req bits: %d\n", pc, config->num_vals, required_bits);
            #endif
            if(num_set_model_selector_bit_pool_bits < required_bits) {
                #ifdef DEBUG
                uint32_t prev_selector_val = set_model_selector_bit_pool;
                uint8_t prev_num_bits = num_set_model_selector_bit_pool_bits;
                #endif
                // Discard the leftover bits in order to keep some locality
                get_fuzz((char *)&fuzzer_val, 1);
                set_model_selector_bit_pool = fuzzer_val;
                num_set_model_selector_bit_pool_bits = 8;                

                #ifdef DEBUG
                printf("[0x%08x] Native Set MMIO: needed to re-fill bit pool. Prev num_bits/val: (%d, %02x). Now: (%d, %04x)\n", pc, prev_num_bits, prev_selector_val, num_set_model_selector_bit_pool_bits, set_model_selector_bit_pool);
                #endif
            }

            // get number of bits from bit pool
            fuzzer_val = set_model_selector_bit_pool & ((1 << required_bits) - 1);
            set_model_selector_bit_pool >>= required_bits;
            num_set_model_selector_bit_pool_bits -= required_bits;
            #ifdef DEBUG
            printf("[0x%08x] Native Set MMIO: chosen index: %d, remaining bit pool: %04x (%d bits)\n", pc, fuzzer_val, set_model_selector_bit_pool, num_set_model_selector_bit_pool_bits);
            #endif
        }
        #endif

        result_val = config->values[fuzzer_val % config->num_vals];
    } else {
        result_val = config->values[0];
    }

    #ifdef DEBUG
    printf("[0x%08x] Native Set MMIO handler: [0x%08lx] = [0x%lx] from input: %x [values: ", pc, addr, result_val, fuzzer_val);
    for (uint32_t i = 0; i < config->num_vals; ++i) {
        if(i) {
            printf(", ");
        }
        printf("%x", config->values[i]);
    }
    printf("]\n");
    #endif

    uc_mem_write(uc, addr, (char *)&result_val, size);
}

uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *vals, int num_ranges) {
    struct constant_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct constant_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        printf("Registering constant model for range: [%x] %lx - %lx with val: %x\n", pcs[i], starts[i], ends[i], vals[i]);
        #endif

        model_configs[i].val = vals[i];

        if(add_mmio_subregion_handler(uc, constant_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }

    }

    return UC_ERR_OK;
}

uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *init_vals, uint32_t *steps, int num_ranges) {
    // TODO: support cleanup, currently we just allocate, hand out pointers and forget about them
    struct linear_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct linear_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        printf("Registering linear model for range: [%x] %lx - %lx with step: %x\n", pcs[i], starts[i], ends[i], steps[i]);
        #endif
        model_configs[i].val = init_vals[i];
        model_configs[i].step = steps[i];

        if(add_mmio_subregion_handler(uc, linear_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint8_t *byte_sizes, uint8_t *left_shifts, uint32_t *masks, int num_ranges) {
    struct bitextract_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct bitextract_mmio_model_config));

    for (int i = 0; i < num_ranges; ++i) {
        model_configs[i].mask = masks[i];
        model_configs[i].byte_size = byte_sizes[i];
        model_configs[i].left_shift = left_shifts[i];
        model_configs[i].mask_hamming_weight = 0;

        uint32_t mask = masks[i];
        while(mask) {
            if(mask & 1) {
                ++model_configs[i].mask_hamming_weight;
            }
            mask >>= 1;
        }

        #ifdef DEBUG
        printf("Registering bitextract model for range: [%x] %lx - %lx with size, left_shift: %d, %d. Mask: %08x, hw: %d\n", pcs[i], starts[i], ends[i], byte_sizes[i], left_shifts[i], masks[i], model_configs[i].mask_hamming_weight);
        #endif

        if(add_mmio_subregion_handler(uc, bitextract_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *value_nums, uint32_t **value_lists, int num_ranges) {
    struct value_set_mmio_model_config *model_configs = calloc(num_ranges, sizeof(struct value_set_mmio_model_config));

    printf("Registering incoming Value Set models\n");

    for (int i = 0; i < num_ranges; ++i) {
        #ifdef DEBUG
        uint32_t pc;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        printf("Registering value set model: [%x] %lx - %lx with numvalues, value_set: %d, [", pcs[i], starts[i], ends[i], value_nums[i]);
        for (uint32_t j = 0; j < value_nums[i]; ++j) {
            if(j) {
                printf(", ");
            }
            printf("%x", value_lists[i][j]);
        }
        printf("]\n");
        #endif

        model_configs[i].num_vals = value_nums[i];
        model_configs[i].values = calloc(value_nums[i], sizeof(**value_lists));
        for (int j = 0; j < value_nums[j]; ++j) {
            model_configs[i].values[j] = value_lists[i][j];
        }

        if(add_mmio_subregion_handler(uc, value_set_mmio_model_handler, starts[i], ends[i], pcs[i], &model_configs[i]) != UC_ERR_OK) {
            return UC_ERR_EXCEPTION;
        }
    }

    return UC_ERR_OK;
}

uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs, int num_addresses) {
    if(num_addresses <= MAX_IGNORED_ADDRESSES) {
        #ifdef DEBUG
        for(int i = 0; i < num_addresses; ++i) {
            printf("Registering passthrough address: [%x] %lx\n", pcs[i], addresses[i]);
        }
        #endif
        memcpy(ignored_addresses, addresses, num_addresses * sizeof(uint64_t));
        memcpy(ignored_address_pcs, pcs, num_addresses * sizeof(uint64_t));
        num_ignored_addresses = num_addresses;
        return UC_ERR_OK;
    } else {
        printf("Too many ignored addresses to be registered");
        return UC_ERR_EXCEPTION;
    }
}

uc_err load_fuzz(const char *path) {
    FILE *fp;

    if(!(fp=fopen(path, "r"))) {
        perror("Opening file failed\n");
        return -1;
    }

    if(fseek(fp, 0L, SEEK_END)) {
        perror("fseek failed\n");
        return -1;
    }

    if((fuzz_size = ftell(fp)) == -1) {
        perror("ftell failed\n");
        return -1;
    }
    rewind(fp);

    if(fuzz_size > PREALLOCED_FUZZ_BUF_SIZE) {
        free(fuzz);
        free(fuzz_scratch_buf);
        if (!(fuzz = malloc(fuzz_size)) || !(fuzz_scratch_buf = malloc(fuzz_size)))
        {
            perror("Allocating fuzz buffer failed\n");
            return -1;
        }
        printf("Allocated new oversized fuzz buffer of size 0x%lx\n", fuzz_size);
    }

    if(fuzz_size && fread(fuzz, fuzz_size, 1, fp) != 1) {
        perror("fread failed\n");
        return -1;
    }

    return 0;
}

uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback, uint64_t start, uint64_t end, uint32_t pc, void *user_data) {
    if(num_mmio_callbacks >= MAX_MMIO_CALLBACKS) {
        printf("ERROR add_mmio_subregion_handler: Maximum number of mmio callbacks exceeded\n");
        return -1;
    }

    if(!num_mmio_regions) {
        printf("ERROR add_mmio_subregion_handler: mmio start and end addresses not configured, yet\n");
        return UC_ERR_EXCEPTION;
    }

    int custom_region = 1;
    for (int i = 0; i < num_mmio_regions; ++i)
    {
        if (! (start < mmio_region_starts[i] || end > mmio_region_ends[i]))
        {
            custom_region = 0;
        }
    }

    if(custom_region) {
        printf("Attaching native listener to custom mmio subregion 0x%08lx-0x%08lx", start, end);
        add_mmio_region(uc, start, end);
    }

    struct mmio_callback *cb = calloc(1, sizeof(struct mmio_callback));
    cb->callback = callback;
    cb->start = start;
    cb->user_data = user_data;
    cb->end = end;
    cb->pc = pc;

    mmio_callbacks[num_mmio_callbacks++] = cb;

    return UC_ERR_OK;
}

uc_err init(uc_engine *uc, int fuzz_mmio, exit_hook_t p_exit_hook, mmio_region_added_cb_t p_mmio_region_added_cb, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, void *p_py_default_mmio_user_data, int max_num_dynamically_added_mmio_pages, uint32_t num_exit_at_bbls, uint64_t *exit_at_bbls, uint32_t num_allowed_irq_numbers, uint8_t *allowed_irq_numbers) {
    // printf("Init called! uc at: %p\n", uc);
    // uc_hook_add(uc, &block_hook_handle, UC_HOOK_BLOCK, hook_block, (void *)0, 1, 0);
    exit_hook = p_exit_hook;

    py_default_mmio_user_data = p_py_default_mmio_user_data;

    for (uint32_t i = 0; i < num_exit_at_bbls; ++i)
    {
        uint64_t tmp;
        uint64_t bbl_addr = exit_at_bbls[i] & (~1LL);
        if (uc_hook_add(uc, &tmp, UC_HOOK_BLOCK, hook_block_exit_at, 0, bbl_addr, bbl_addr) != UC_ERR_OK)
        {
            perror("Could not register exit-at block hook...\n");
            return -1;
        }
    }

    if((!(fuzz = malloc(PREALLOCED_FUZZ_BUF_SIZE))) || (!(fuzz_scratch_buf = malloc(PREALLOCED_FUZZ_BUF_SIZE)))) {
        perror("Allocating fuzz buffer failed\n");
        return -1;
    }

    if(fuzz_mmio) {
        mmio_region_added_cb = p_mmio_region_added_cb;
        max_extra_pages = max_num_dynamically_added_mmio_pages;

        // Register unconditional hooks for mmio regions for handler presence
        num_mmio_regions = p_num_mmio_regions;
        mmio_region_starts = calloc(num_mmio_callbacks, sizeof(*p_mmio_starts));
        mmio_region_ends = calloc(num_mmio_callbacks, sizeof(*p_mmio_ends));
        memcpy(mmio_region_starts, p_mmio_starts, num_mmio_regions * sizeof(*p_mmio_starts));
        memcpy(mmio_region_ends, p_mmio_ends, num_mmio_regions * sizeof(*p_mmio_ends));

        for (int i = 0; i < num_mmio_regions; ++i) {
            if(add_mmio_region(uc, mmio_region_starts[i], mmio_region_ends[i]) != UC_ERR_OK) {
                perror("[native init] could not register mmio region.\n");
                return UC_ERR_EXCEPTION;
            }
        }
    } else {
        max_num_dynamically_added_mmio_pages = 0;
    }

    // Fuzzer-triggered interrupts
    if(num_allowed_irq_numbers) {
        printf("[NATIVE] init: registering %d fuzzable irqs: [ ", num_allowed_irq_numbers);
        for (uint32_t i = 0; i < num_allowed_irq_numbers; ++i)
        {
            uint8_t irq = allowed_irq_numbers[i];
            printf("%d ", irq);
            // Do some sanity checking on what we are actually about to invoke. Stuff like hardfault handlers or reboots is not one of them
            if(irq < 15) {
                perror("[NATIVE ERROR] init: cannot allow fuzzing internal interrupts\n");
                exit(-1);
            }
            allowed_fuzzed_irqs[irq] = 1;
        }
        puts("]");
        allow_fuzzer_injected_interrupts = 1;
    } else {
        allow_fuzzer_injected_interrupts = 0;
    }

    return UC_ERR_OK;
}

/* Native Features
Required:
    - timer: invoke callback/raise interrupt every n ticks
    - nvic

Optional:
    - collect (and dump) bb/mmio/ram trace
    
*/
