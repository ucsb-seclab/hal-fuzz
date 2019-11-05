#!/usr/bin/env python3
import svgwrite
import parse
import sys
from dataclasses import dataclass, field
import gc

# TODO: visualization with non 4-byte regions
# For example: chunk cell into multiple rectangles
# Caveat: need to normalize changing sizes for same offset

# TODO: visualize the number of accesses (maybe transparency-based?)

from os import listdir
from os.path import isfile, join

parse_fmt = "{:04x}: {:x} {:x} {} {:d} 0x{:08x}"
def parse_mmio_trace(filename):
    with open(filename, "r") as f:
        lines = f.readlines()

    records = []
    # "{:04x}: {:x} {} {:d} 0x{:08x}:{:x}".format(event_id, pc, mode, size, address, value)
    for line in lines:
        if line == "":
            continue
        header = line[:line.rindex(':')]
        try:
            val_string = line[line.rindex(':') + 1:].rstrip()
            vals = list(map(lambda x: int(x, 16), val_string.split(" ")))
            event_id, pc, lr, mode, size, address = parse.parse(parse_fmt, header)
            records.append((event_id, pc, mode, size, address, vals))
        except TypeError:
            print("could not unpack line: {}".format(header))
            exit(-1)
        # print(event_id, pc, mode, size, address, vals)

    return records

@dataclass
class AccessCount:
    num_reads: int = 0
    num_writes: int = 0

def create_access_count():
    return [{4: AccessCount(), 2: AccessCount(), 1: AccessCount()}, {1: AccessCount()}, {2: AccessCount(), 1: AccessCount()}, {1: AccessCount()}]

@dataclass
class MMIOSlot:
    # per in_slot_offset, record the numbers of discrete accesses
    # assumption about aligned accesses: 
    # offset 0 can be accessed in 4, 2, 1 byte chunks, offset 1 only as single byte, ...
    # This may be more information than we care about but we want to draw a picture which is as accurate as possible to start with
    access_counts: list = field(default_factory=create_access_count)
    size: int = 4    


weird_region_addrs = set()
weird_region_count = 0
def get_regions(mmio_accesses):
    global weird_region_addrs, weird_region_count
    
    res = {}

    for event_id, pc, mode, size, address, vals in mmio_accesses:
        region_addr = address & (~0xff)
        
        if not (0x40000000 <= region_addr < 0x50000000):
            if region_addr not in weird_region_addrs:
                weird_region_addrs.add(region_addr)
                weird_region_count += 1
                print("WARNING: odd region found: 0x{:08x}".format(region_addr))

        offset = address - region_addr
        aligned_offset = offset & (~0x3)
        in_slot_offset = offset & 0x3
        
        if region_addr not in res:
            res[region_addr] = {}
        
        if aligned_offset not in res[region_addr]:
            res[region_addr][aligned_offset] = MMIOSlot()
        
        slot = res[region_addr][aligned_offset]

        #if res[region_addr][aligned_offset].size != size:
        #    print("Expected size of an mmio access to not change. Got {} vs. {} for address 0x{:08x} though".format(res[region_addr][aligned_offset].size, size, region_addr + aligned_offset))
        #    if res[region_addr][aligned_offset].size < size:
        #        res[region_addr][aligned_offset].size = size

        if mode == "w":
            slot.access_counts[in_slot_offset][size].num_writes += len(vals)
        else:
            assert(mode == "r")
            slot.access_counts[in_slot_offset][size].num_reads += len(vals)

    if weird_region_count > 10:
        print("[ERROR] We got a lot of non-mmio region pages, this will probably blow up the svg, exiting")
        #for addr in weird_region_addrs:
        print(",".join(map(hex, weird_region_addrs)))
        exit(1)

    return res

COL_WIDTH = 28
COL_GAP = 2
VERT_MARGIN = 3
ROW_HEIGHT = 4
BYTES_PER_CELL = 4
# TODO: variable region sizes
REGION_SIZE = 0x100

TEXT_VERT_OFFSET = 2.5
TEXT_HOR_OFFSET = 1

# In order to be able to draw cells properly, make width divisible
assert(COL_WIDTH % BYTES_PER_CELL == 0)

# Set the opacity based on how many combined reads/writes happened on a slot
opacity_bounds = [
    [0, 1.0],   # no accesses, just full black
    [1, 0.33],  # very limited amount of accesses, faded
    [10, 0.66], # rather small, but not one-time style access counts
    [100, 1.0]  # many accesses: fully show
]

# num_reads/num_writes values
# red: writes
# blue: reads
# [reads/writes, (red,green,blue)]
color_bounds = [
    [0, 'rgb(255, 0, 0)'], # only writes: red
    [0.10, 'rgb(255, 0, 96)'], # mostly writes heavy: reddish
    [0.40, 'rgb(255, 0, 176)'],  # write heavy: 
    [0.80, 'rgb(255, 0, 255)'],  # balanced
    [0.80**-1, 'rgb(176, 0, 255)'],  # read heavy
    [0.40 ** -1, 'rgb(96, 0, 255)'], # mostly reads
    [0.10 ** -1, 'rgb(0, 0, 255)'], # only reads
]

def add_slot(svg_doc, x, y, text=None, color='white', fill_opacity=1.0, subslot_offset=0, num_subslots=BYTES_PER_CELL, stroke_width=0.5):
    shrink_value = (BYTES_PER_CELL-num_subslots)*(float(ROW_HEIGHT)/5.0)
    
    svg_doc.add(svg_doc.rect(
        insert=(x+subslot_offset*(COL_WIDTH/BYTES_PER_CELL)+0.5*shrink_value, y+0.5*shrink_value),
        size=(COL_WIDTH/(BYTES_PER_CELL/num_subslots)-shrink_value, ROW_HEIGHT-shrink_value),
        fill=color,
        stroke='black',
        style='stroke-width:{};fill-opacity:{}'.format(stroke_width, fill_opacity)
    ))

    if text is not None:
        svg_doc.add(svg_doc.text(
            text,
            insert=(x + TEXT_HOR_OFFSET, y + TEXT_VERT_OFFSET),
            style="font-size: 2"
        ))

def get_color(num_reads, num_writes):
    if num_writes == 0:
        if num_reads == 0:
            return 'rgb(0, 0, 0)', 1.0
        else:
            return 'rgb(0, 0, 255)', 1.0
    
    ratio = float(num_reads) / float(num_writes)
    num_accesses = num_reads + num_writes
    res_color, res_opacity = None, None

    for bound, color in color_bounds[::-1]:
        if ratio >= bound:
            res_color = color
            break
    
    for bound, opacity in opacity_bounds[::-1]:
        if num_accesses >= bound:
            res_opacity = opacity
            break

    return res_color, res_opacity

def add_region(svg_doc, x, y, region_base, region_accesses):
    """
    @param region_accesses map of offset -> [writes]
    @return y-axis distance covered
    """
    # num_rows = 2 * len(region_accesses.keys()) + 
    num_rows = 0

    # TODO: sizes != 4

    objs = []
    consecutive_off = 0
    row_y = y

    add_slot(svg_doc, x, row_y, "     0x{:08x}     ".format(region_base), stroke_width=1)
    num_rows += 1
    row_y += ROW_HEIGHT

    for offset in sorted(region_accesses.keys()):
        slot = region_accesses[offset]
        
        if offset != consecutive_off:
            # add ... line
            add_slot(svg_doc, x, row_y, "...")
            row_y += ROW_HEIGHT
            num_rows += 1
        
        # Here we are putting in some ugly logic to draw different sizes within one slot...
        # 1. full 4 byte-sized reads
        num_full_reads = slot.access_counts[0][4].num_reads
        num_full_writes = slot.access_counts[0][4].num_writes
        color, opacity = get_color(num_full_reads, num_full_writes)
        add_slot(svg_doc, x, row_y, '{:02x}: {:d}r / {:d}w'.format(offset, num_full_reads, num_full_writes), color, fill_opacity=opacity)
        # 2. 2 byte-sized reads
        num_left_half_reads = slot.access_counts[0][2].num_reads
        num_left_half_writes = slot.access_counts[0][2].num_writes
        num_right_half_reads = slot.access_counts[2][2].num_reads
        num_right_half_writes = slot.access_counts[2][2].num_writes
        # draw left half (if present)
        if num_left_half_reads != 0 or num_left_half_writes != 0:
            color, opacity = get_color(num_left_half_reads, num_left_half_writes)
            add_slot(svg_doc, x, row_y, color=color, subslot_offset=0, num_subslots=2, stroke_width=0.2, fill_opacity=opacity)
        # draw right half (if present)
        if num_right_half_reads != 0 or num_right_half_writes != 0:
            color, opacity = get_color(num_right_half_reads, num_right_half_writes)
            add_slot(svg_doc, x, row_y, color=color, subslot_offset=2, num_subslots=2, stroke_width=0.2, fill_opacity=opacity)
        # draw single slots
        for i in range(4):
            num_single_slot_reads = slot.access_counts[i][1].num_reads
            num_single_slot_writes = slot.access_counts[i][1].num_writes
            if num_single_slot_reads != 0 or num_single_slot_writes != 0:
                color, opacity = get_color(num_single_slot_reads, num_single_slot_writes)
                add_slot(svg_doc, x, row_y, color=color, subslot_offset=i, num_subslots=1, stroke_width=0.1, fill_opacity=opacity)


        num_rows += 1
        row_y += ROW_HEIGHT

        consecutive_off = offset + BYTES_PER_CELL

    if consecutive_off != region_base + REGION_SIZE:
        add_slot(svg_doc, x, row_y, "...")
        
        num_rows += 1
        row_y += ROW_HEIGHT

    """
    svg_doc.add(svg_doc.rect(
        insert=(x, y),
        size=(COL_WIDTH, height),
        fill='white',
        stroke='black'
    ))
    """

    #for obj in objs:
    #    svg_doc.add(obj)


    #if 0 not in region_accesses:
    #    num_rows -= 1

    height = num_rows * (ROW_HEIGHT)
    
    # print("added region of height: {}".format(height))
    return height

def main():
    if len(sys.argv) != 3:
        print("Usage: {} <trace_dir> <outfile_name>".format(sys.argv[0]))
        exit(1)

    trace_dir = sys.argv[1]
    outfile_name = sys.argv[2]
    x, y = 0, 0
    
    files = [f for f in listdir(trace_dir) if isfile(join(trace_dir, f)) and f.startswith("mmio_")]
    # print("Got files: {}".format(files))

    total_width = len(files) * (COL_WIDTH + COL_GAP)

    svg_doc = svgwrite.Drawing(filename=outfile_name, size=(total_width, 600))

    used_offsets = {}
    traces = []
    # draw one trace in a column
    for trace_file in files:
        mmio_records = parse_mmio_trace(join(trace_dir, trace_file))
        regions = get_regions(mmio_records)
        traces.append((trace_file, regions))

        # collect actually used offsets for each region
        for region_base, region_accesses in regions.items():
            if region_base not in used_offsets:
                used_offsets[region_base] = set()
            
            for offset in region_accesses.keys():
                used_offsets[region_base].add(offset)

    for filename, regions in traces:
        gc.collect()
        print("Working on region for: {}".format(filename))
        svg_doc.add(svg_doc.text(
            filename,
            insert=(x + TEXT_HOR_OFFSET, y + TEXT_VERT_OFFSET),
            style="font-size: 1"
        ))
        y += ROW_HEIGHT

        # Add regions used elsewhere but not here for alignment
        for region_base in used_offsets.keys():
            if region_base not in regions:
                regions[region_base]={}

        # draw each region within a column
        for region_addr in sorted(regions.keys()):
            region_accesses = regions[region_addr]

            # add slots that are used in other trace for alignment
            for offset in used_offsets[region_addr]:
                if offset not in region_accesses:
                    region_accesses[offset] = MMIOSlot()
            
            # print("0x{:x}".format(region_addr))
            height = add_region(svg_doc, x, y, region_addr, region_accesses)
            y += height + VERT_MARGIN
            
        
        # move to next column
        y = 0
        x += COL_WIDTH + COL_GAP

        traces.remove((filename, regions))
    
    print("Writing svg file: {}".format(outfile_name))
    svg_doc.save()
    print("Done!")
    
    


if __name__ == "__main__":
    main()