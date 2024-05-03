# ！/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project: pypidstat
@File: test_netstat
@Author: thirsd@sina.com
@Date: 2024/5/1 18:41
"""

import asyncio
from typing import Dict, Tuple

from pypidstat.net import NetCapStat


def test_net_cap():
    loop = asyncio.new_event_loop()
    print(f"{'pid':<10} {'send_cnt':<15} {'send_bytes':<15} {'recv_cnt':<15} {'recv_bytes':<15}")

    def handle_call_back(traffic_pid: Dict[int, Tuple], traffic_pid_conn: Dict[int, Dict[str, Tuple]]):
        for pid, traffic in traffic_pid.items():
            print(f"{pid:<10} {traffic[0]:<15} {traffic[1]:<15} {traffic[2]:<15} {traffic[3]:<15}")

    net_stat = NetCapStat(dev='eth0', loop=loop, cmd_regex='.*proxy.*', interval=2, call_back=handle_call_back,
                          filter_exp="port 7000")
    net_stat.start()

    net_stat.join()


if __name__ == "__main__":
    test_net_cap()
