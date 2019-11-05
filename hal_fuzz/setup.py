#!/usr/bin/env python
"""
    This is our Python package for HAL-Fuzz and related projects.
"""
import os, sys
from distutils.command.build import build
from setuptools import setup
import subprocess

class Build(build):
    """Customized setuptools build command - builds native unicorn bindings on build."""
    def run(self):
        protoc_command = ["make", "-C", "hal_fuzz/native", "clean", "all"]
        if subprocess.call(protoc_command) != 0:
            sys.exit(-1)
        build.run(self)

def get_packages(rel_dir):
    packages = [rel_dir]
    for x in os.walk(rel_dir):
        # break into parts
        base = list(os.path.split(x[0]))
        if base[0] == "":
            del base[0]

        for mod_name in x[1]:
            packages.append(".".join(base + [mod_name]))

    return packages


setup(name='hal_fuzz',
    version='0.1',
    description='This is the Python library for HAL-fuzz and related projects',
    author='Eric Gustafson, Tobias Scharnowski',
    author_email='edg@cs.ucsb.edu, tobias.scharnowski@rub.de',
    url='https://seclab.cs.ucsb.edu',
    packages=get_packages('hal_fuzz'), requires=['PyYAML','intelhex'],
    include_package_data=True,
    # package_data={'native':['native/native_hooks.so']},
    cmdclass = {
      'build': Build,
    },
    entry_points = {
        'console_scripts': [
            'halfuzz = hal_fuzz.harness:main',
        ]
    }
)
