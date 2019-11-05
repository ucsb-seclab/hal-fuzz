#!/usr/bin/env python3
from sys import argv
import os
import glob

if len(argv) != 2:
    print("Usage: {} <base_dir>".format(argv[0]))
    exit(0)

base_dir=argv[1]

for dirpath, dirnames, filenames in os.walk(base_dir):
    if not ("crashes" in dirnames and not dirpath.endswith("/traces")):
        continue
    
    crash_mod_times = [os.path.getmtime(path) for path in glob.glob(os.path.join(dirpath, "crashes") + "/id:000000,*", recursive=False)]
    print(dirpath)
    if not crash_mod_times:
        print("No crash...")
    else:
        queue_mod_times = [os.path.getmtime(path) for path in glob.glob(os.path.join(dirpath, "queue") + "/id:000001,*", recursive=False)]

        diff = min(crash_mod_times) - max(queue_mod_times)
        print("Hours to crash: {:.2f}".format(diff/float(3600)))