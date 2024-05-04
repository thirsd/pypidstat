# ！/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project: pypidstat
@File: setup.py
@Author: thirsd@sina.com
@Date: 2024/5/4 17:30
"""

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pypidstat",
    version="0.1",
    author="thirsd",
    author_email="thirsd@sina.com",
    description="python to implement pidstat and nethogs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitee.com/thirsd/pypidstat",
    packages=setuptools.find_packages(),
    install_requires=['dpkt>=1.9.8', 'libpcap>=1.11.0b2', 'pypcap>=1.3.0'],
    entry_points={
        'console_scripts': [
            'pypidstat=pypidstat:main'
        ],
    },
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL V2 License",
        "Operating System :: OS Independent",
    ),
)