# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
from lib.cmd import brutespray
setup(
    name='brutespray',
    version="1.0",
    packages=find_packages(),
    include_package_data=False,
with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(...
install_requires=required,
...)