# ！/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project: pypidstat
@File: test_format_str
@Author: thirsd@sina.com
@Date: 2024/5/2 16:11
"""


if __name__ == "__main__":
    from pypidstat.utils import format_float_str

    print(format_float_str(100000, 8, 1))
    print(format_float_str(1000, 5, 0))
