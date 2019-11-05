#!/usr/bin/env python3
import yaml
import argparse
from os.path import isfile
from itertools import chain

def _merge_dict(dct, merge_dct):
    for k, v in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], dict)):
            _merge_dict(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]

def merge_and_write(dest_yml_path, source_map):
    with open(dest_yml_path, 'rb') as infile:
        config = yaml.load(infile)

    _merge_dict(config, source_map)

    # Use hex representation of numbers in generated yml file
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))
    yaml.add_representer(int, hexint_presenter)

    # print("About to merge back: {}".format(config))
    with open(dest_yml_path, "w") as f:
        f.write(yaml.dump(config, default_flow_style=False))

parser = argparse.ArgumentParser(description="Add a set of resolved symbols to a configuration file")
parser.add_argument('source_config', help="Path to yml config file to be merged into all others.")
parser.add_argument('dest_configs', help="The yml config files to apply the changes to.", nargs='+')
args = parser.parse_args()

if any([not (path.endswith(".yml") and isfile(path)) for path in chain([args.source_config], args.dest_configs)]):
    print("Error: not all files exist and end on '.yml'")
    exit(1)

with open(args.source_config, 'rb') as infile:
    source_config = yaml.load(infile)

for dest_config_path in args.dest_configs:
    merge_and_write(dest_config_path, source_config)
