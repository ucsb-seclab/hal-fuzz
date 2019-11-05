import re

# 112f: 12b6 1617 r 4 0x40094008:7c6e5ef4 7c7c7c7c f45e5e7c 5e7f5e5e 5e115f 5e000400 687f7f5e 5e5e405e 5e5e5e5e 1002a2a ff2a2a2a 2a2a2a7f 2a2a2a2a 2a2a2a2a 2a2a2a2a 2b1b2a2a 20050e00 ffff1900 5e5f78ff 97979797 2a2a2a2a 2a2a2a2a 2a3a2a2a
mmio_regex = re.compile(r"([0-9a-f]+): ([0-9a-f]+) ([0-9a-f]+) ([rw]) ([\d]) (0x[0-9a-f]+)\:(.*)")
def parse_mmio_line(line):
    event_id, pc, lr, mode, size, address, val_text = mmio_regex.match(line).groups()
    # print("Got result: {}".format((event_id, pc, mode, size, address, val_text)))

    address = int(address, 16)
    event_id = int(event_id, 16)
    size = int(size)
    pc = int(pc, 16)
    lr = int(lr, 16)

    return event_id, pc, lr, mode, size, address, val_text

# 0000 11c4 0
bb_regex = re.compile(r"([0-9a-f]+) ([0-9a-f]+) ([0-9]+)")
def parse_bb_line(line):
    event_id, pc, cnt = bb_regex.match(line).groups()
        
    # print("Got result: {}".format((event_id, pc, mode, size, address, val_text)))
    event_id = int(event_id, 16)
    pc = int(pc, 16)
    cnt = int(cnt)

    return event_id, pc, cnt

# 0001: 11c4 0 r 4 0x000011e0:7d54 7d54
def parse_ram_line(line):
    return parse_mmio_line(line)

def _parse_file(filename, line_parser):
    with open(filename, "r") as f:
        return [line_parser(line) for line in f.readlines() if line]

def parse_mmio_trace(filename):
    return parse_mem_trace(filename)

def parse_mem_trace(filename):
    return _parse_file(filename, parse_mmio_line)

def parse_bbl_trace(filename):
    return _parse_file(filename, parse_bb_line)


def dump_mem_line(event_id, pc, lr, mode, size, address, values):
    pl = "{:04x}: {:x} {:x} {} {:d} 0x{:08x}:{:x}".format(event_id, pc, lr, mode, size, address, values[0])
    
    for value in values[1:]:
        pl += " {:x}".format(value)
    
    return pl

def dump_bbl_line(event_id, bb_addr, count):
    return "{:04x} {:x} {:d}".format(event_id, bb_addr, count)