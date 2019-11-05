import dpkt
import os
import sys

MTU_SIZE = 1520

outf = open(sys.argv[2], 'wb')
dst_mac = sys.argv[3].replace(":","").decode('hex')
all_fs = '\xff\xff\xff\xff\xff\xff'
with open(sys.argv[1], 'rb') as f:
    r = dpkt.pcapng.Reader(f)
    for ts, buf in r:
        topad = MTU_SIZE - len(buf)
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.dst != dst_mac and eth.dst != all_fs:
            continue
        # filter
        buf = buf + '\0' * topad
        assert(len(buf) == MTU_SIZE)
        outf.write(buf)

outf.close()

