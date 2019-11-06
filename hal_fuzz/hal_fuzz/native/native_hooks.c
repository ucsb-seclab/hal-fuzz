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


uc_hook block_hook_handle = 0;
uc_hook code_hook_handle = 0;

// ~1 MB of preallocated fuzzing buffer size
#define PREALLOCED_FUZZ_BUF_SIZE 1000000
#define MMIO_HOOK_PC_ALL_ACCESS_SITES (0xffffffffuL)

char *fuzz = (char *) 0;
char *fuzz_scratch_buf = (char *) 0;
unsigned long fuzz_size = 0;
unsigned long fuzz_cursor = 0;

uc_hook hook_block_cond_py_handlers_handle;
uc_cb_hookcode_t py_hle_handler_hook = (uc_cb_hookcode_t)0;
int num_handlers = 0;
uint64_t *bb_handler_locs = 0;

void *py_default_mmio_user_data = NULL;

void do_exit(int status, int sig){
    puts("Defaulting to exit(0)");
    exit(status);
}

void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

void get_fuzz(char *buf, uint32_t size) {

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


int num_extra_pages = 0;
int max_extra_pages = 0;
bool hook_unmapped_mem_access(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    if(num_extra_pages < max_extra_pages) {
        uint32_t pc, lr;
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


uc_err init(uc_engine *uc, int fuzz_mmio, exit_hook_t p_exit_hook, mmio_region_added_cb_t p_mmio_region_added_cb, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, void *p_py_default_mmio_user_data, int max_num_dynamically_added_mmio_pages, uint32_t num_exit_at_bbls, uint64_t *exit_at_bbls, uint32_t num_allowed_irq_numbers, uint8_t *allowed_irq_numbers) {
    printf("Init called! uc at: %p\n", uc);
    // uc_hook_add(uc, &block_hook_handle, UC_HOOK_BLOCK, hook_block, (void *)0, 1, 0);

    if((!(fuzz = malloc(PREALLOCED_FUZZ_BUF_SIZE))) || (!(fuzz_scratch_buf = malloc(PREALLOCED_FUZZ_BUF_SIZE)))) {
        perror("Allocating fuzz buffer failed\n");
        return -1;
    }

    max_num_dynamically_added_mmio_pages = 0;


    return UC_ERR_OK;
}

/* Native Features
Required:
    - timer: invoke callback/raise interrupt every n ticks
    - nvic

Optional:
    - collect (and dump) bb/mmio/ram trace
    
*/
