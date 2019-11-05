#!/usr/bin/env python3

from sys import argv
import re

if len(argv) < 3:
    print("Usage: {} <out_filename> <trace_file_1> <trace_file_2> [ ... <trace_file_n>]".format(argv[0]))
    exit(-1)

traces = []
for i in range(2, len(argv)):
    with open(argv[i], "r") as f:
        trace_lines = f.readlines()
        if trace_lines[-1].strip() == "":
            trace_lines = trace_lines[:-1]
        traces.append(trace_lines)

hex_regex = re.compile("^([0-9a-f]+)[^0-9a-f].*$")
def get_event_id(line):
    return int(hex_regex.match(line).group(1), 16)

curr_ids = list(map(lambda trace: get_event_id(trace[0]), traces))
curr_indices = len(traces)*[0]

res = ""

while curr_ids.count(0xffffffff) < len(traces):  # or ram_ind < len(ram_trace_lines):
    trace_ind = curr_ids.index(min(curr_ids))

    line = traces[trace_ind][
        curr_indices[trace_ind]
    ]
    curr_indices[trace_ind] += 1
    if curr_indices[trace_ind] >= len(traces[trace_ind]):
        curr_ids[trace_ind] = 0xffffffff
    else:
        curr_ids[trace_ind] = get_event_id(traces[trace_ind][curr_indices[trace_ind]])

    res += line
        

print("Writing out to file: {}".format(argv[1]))
with open(argv[1], "w") as f:
    f.write(res)
