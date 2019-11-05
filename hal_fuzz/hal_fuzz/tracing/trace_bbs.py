from unicorn import UC_MEM_WRITE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from ..exit import add_exit_hook,do_exit
from ..handlers import add_block_hook
from .trace_ids import next_event_id
from .serialization import dump_bbl_line


outfile = None
bb_addrs = []
curr_cycle_len = 0
curr_cycle_offset = 0
MAX_CYCLE_LEN = 4
def collect_bb_addr(uc, address, size, user_data):
    global curr_cycle_len
    global curr_cycle_offset
    found = False

    if curr_cycle_len != 0 and bb_addrs[-curr_cycle_len + curr_cycle_offset][1] == address:
        bb_addrs[-curr_cycle_len + curr_cycle_offset][2] += 1
        curr_cycle_offset = (curr_cycle_offset + 1) % curr_cycle_len
    else:
        curr_cycle_len = 0

        if bb_addrs:
            if bb_addrs and bb_addrs[-1][1]==address:
                bb_addrs[-1][2] += 1
                return

        if len(bb_addrs) >= 2*MAX_CYCLE_LEN:
            for prefix_len in range(MAX_CYCLE_LEN, 1, -1):
                if found:
                    break
                # Start of cycle fits
                if address == bb_addrs[-prefix_len][1] == bb_addrs[-2*prefix_len][1]:
                    found = True
                    for i in range(1, prefix_len):
                        if bb_addrs[-prefix_len + i][1] != bb_addrs[-2 * prefix_len + i][1]:
                            found = False
                            break

                    # We found a cycle. Tick up the counters and set the current cycle metadata
                    if found:
                        curr_cycle_len = prefix_len
                        curr_cycle_offset = 1
                        bb_addrs[-prefix_len][2] += 1
                        return

        bb_addrs.append([next_event_id(), address, 0])


def collect_bb_addr_no_cyclic_compression(uc, address, size, user_data):
    if bb_addrs and bb_addrs[-1][1]==address:
        bb_addrs[-1][2] += 1
    else:
        bb_addrs.append([next_event_id(), address, 0])

def dump_bb_trace(uc):
    pl = ""
    for event_id, bb_addr, count in bb_addrs:
        pl += dump_bbl_line(event_id, bb_addr, count)+"\n"

    with open(outfile, "w") as f:
        f.write(pl)

    print("Dumped bb trace access trace to {}".format(outfile))

def register_handler(uc, trace_file):
    global outfile

    if trace_file is not None:
        add_block_hook(collect_bb_addr)
        outfile = trace_file
        add_exit_hook(dump_bb_trace)
