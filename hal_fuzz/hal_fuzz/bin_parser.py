"""
    Tools to help with parsing useful bits out of firmware binaries
"""
import struct


class M3Parser:
    def __init__(self, filename):
        self.filename = filename
        with open(self.filename, "rb") as f:
            sp_bad_endian = f.read(4)
            self.initial_sp = struct.unpack("I", sp_bad_endian)[0]
            entry_point_bad_endian = f.read(4)
            self.entry_point = struct.unpack("I", entry_point_bad_endian)[0]

    def get_entry_point(self):
        return self.entry_point

    def get_initial_sp(self):
        return self.initial_sp
