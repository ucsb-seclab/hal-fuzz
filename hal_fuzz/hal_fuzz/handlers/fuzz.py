from unicorn.arm_const import *
from .. import native

def parse_fuzzed_irqs(entries):
    allowed_irqs = set()
    print("Parsing fuzzable irq configuration")
    for name, int_or_range_string in entries.items():
        # print("[PARSE FUZZED IRQs] Looking at entry: {} -> {}".format(name, int_or_range_string))
        if isinstance(int_or_range_string, int):
            allowed_irqs.add(int_or_range_string)
        elif isinstance(int_or_range_string, str):
            for entry in int_or_range_string.replace(" ", "").replace("\t", "").split(","):
                if "-" in entry:
                    start, end = map(int, entry.split("-"))
                    print("Adding fuzzable irq range: {}-{}".format(start, end))
                    assert(start <= end)
                    for i in range(start, end + 1):
                        allowed_irqs.add(i)
                else:
                    print("Adding fuzzable irq entry: {}".format(entry))
                    allowed_irqs.add(int(entry))
        else:
            assert(False)

    return allowed_irqs

def get_fuzz(size):
    """
    Gets at most 'size' bytes from the fuzz pool.

    If we run out of fuzz, something will happen (e.g., exit)
    :param size:
    :return:
    """
    return native.get_fuzz(size)

def fuzz_remaining():
    return native.fuzz_remaining()

def load_fuzz(file_path):
    native.load_fuzz(file_path)

def return_fuzz_byte(uc):
    global fuzz
    c = get_fuzz(1)
    # TODO: This is not generic, add archinfo here to find the ret regs
    uc.reg_write(UC_ARM_REG_R0, ord(c))
