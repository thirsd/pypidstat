# ！/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project: pypidstat
@File: test_procstat
@Author: thirsd@sina.com
@Date: 2024/5/1 18:42
"""

import asyncio
from typing import Dict, Tuple

from core import ProcessStat
from pypidstat.net import NetCapStat
import time


def test_process():
    pid = 3092
    itv = 2
    prev_ps_stat = ProcessStat(proc_id=pid)
    prev_ps_stat.init()
    time.sleep(itv)
    curr_ps_stat = ProcessStat(proc_id=pid)
    curr_ps_stat.init()
    print(f"total_memory: {curr_ps_stat.get_whole_memory()}")
    print(f"cpu_loads: {curr_ps_stat.get_cpu_loads(prev_ps_stat, itv)}")
    print(f"ctx_switch_loads: {curr_ps_stat.get_ctx_switch_loads(prev_ps_stat, itv)}")
    print(f"fd_net_count: {curr_ps_stat.get_fd_net_count()}")
    print(f"get_io_loads: {curr_ps_stat.get_io_loads(prev_ps_stat, itv)}")
    print(f"get_mem_loads: {curr_ps_stat.get_mem_loads(prev_ps_stat, itv)}")
    print(f"get_net_loads: {curr_ps_stat.get_net_loads(prev_ps_stat, itv)}")
    print(f"get_stack_loads: {curr_ps_stat.get_stack_loads(prev_ps_stat, itv)}")
    print(f"get_fd_net_info: {curr_ps_stat.fd_info}")


if __name__ == "__main__":
    test_process()
