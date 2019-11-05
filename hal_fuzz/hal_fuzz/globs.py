debug_enabled = False
input_file_name = None
uc = None
regions = {}

# Make sure those match with what is specified in the native code
MMIO_HOOK_PC_ALL_ACCESS_SITES = 0xffffffff
EXIT_AT_NONE = 0xffffffff

DEFAULT_NUM_NVIC_VECS = 128
NVIC_VTOR_NONE = 0xffffffff
NVIC_EXCEPT_MAGIC_RET_MASK = 0xfffffff0

DEFAULT_BASIC_BLOCK_LIMIT = 20000000
DEFAULT_MAX_NUM_DYN_ALLOC_MMIO_PAGES = 16
