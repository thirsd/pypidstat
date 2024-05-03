# ！/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project: pypidstat
@File: test_net_dev
@Author: thirsd@sina.com
@Date: 2024/5/3 11:44
"""

from pypidstat.net import get_dev_interface


def test_net_dev():
    from pprint import pprint
    pprint(get_dev_interface())


if __name__ == "__main__":
    test_net_dev()
