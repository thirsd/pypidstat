# ！/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project: pypidstat
@File: net_cap.py
@Author: thirsd@sina.com
@Date: 2024-4-29 20:59
"""
import asyncio
import copy

import dpkt
import pcap
import socket
import threading
from queue import Queue, Empty
from typing import List, Callable, Optional, Dict, Tuple

from pypidstat.core.process_stat import ProcSys


class ThreadEventLoop(threading.Thread):
    def __init__(self, loop: asyncio.AbstractEventLoop, name: str = None):
        super().__init__()
        self._loop = loop
        self.daemon = True
        if name is not None:
            self.name = name

    def run(self) -> None:
        self._loop.run_forever()


class ThreadNetCap(threading.Thread):
    def __init__(self, dev: str, queue: Queue, filter_exp: str = None, name: str = None):
        super().__init__()
        self.setDaemon(True)
        if name is not None:
            self.name = name

        if queue is None:
            raise Exception("ThreadNetCap's args is invalid, queue is None")
        else:
            self._queue = queue
        self._filter_exp = filter_exp

        # 标志线程的运行状态
        self.run_flag = True

        # 初始化网络监听
        self._pcap = pcap.pcap(dev, promisc=False, immediate=False, timeout_ms=50)
        if self._filter_exp is not None:
            self._pcap.setfilter(self._filter_exp)

    def run(self):
        for cap_time, cap_raw in self._pcap:
            # time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cap_time))
            eth = dpkt.ethernet.Ethernet(cap_raw)
            # Make sure the Ethernet frame contains an IP packet
            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                src_ip, dst_ip, src_port, dst_port, tcp_len \
                    = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), tcp.sport, tcp.dport, len(tcp)
                # print(f'{src_ip}:{src_port} ==> {dst_ip}:{dst_port}, {cap_time} ')
                self._queue.put((cap_time, src_ip, src_port, dst_ip, dst_port, tcp_len))

            # 如果已经执行stop标识，则退出
            if not self.run_flag:
                break

    def stop(self) -> None:
        self.run_flag = False
        self._pcap.close()


class NetCapStat(threading.Thread):
    def __init__(self, loop: asyncio.AbstractEventLoop, dev: str, pids: Optional[List[int]] = None,
                 cmd_regex: str = None, filter_exp: str = None, interval: int = 10,
                 call_back: Callable[[Dict, Dict], None] = None):
        super().__init__()
        self._loop = loop

        self._itv = interval
        if pids is not None and isinstance(pids, List):
            self._pids = pids
            self._cmd_regex = None
        else:
            self._pids = None
            self._cmd_regex = cmd_regex

        self.setDaemon(True)
        self._sys_proc = ProcSys()

        self.run_flag = True

        self._call_back = call_back
        self._conn_map: Dict = {}
        self._queue = Queue()
        self._cap_thread = ThreadNetCap(dev=dev, queue=self._queue, filter_exp=filter_exp, name="pidstat_pcap_thread")

        self._addr_pid_map: Dict[str, int] = {}
        self._traffic_pid_map: Dict[int, List] = {}
        self._traffic_pid_conn_map: Dict[int, Dict[str, List]] = {}

    def _get_conns(self) -> Dict[int, Dict]:
        """
        获取指定进程的网络connection列表，pids指定则使用指定列表，否则根据cmd_regex获取匹配的进程PID列表
        Returns:
            返回进程的网络连接字典。key为进程PID，value为进程的连接字典{conn_key, conn_dict}
        """
        all_conns_dict = {}

        # 如果指定初始化指定pids，则直接使用指定的pids；否则，使用cmd_regex进行匹配，当cmd_regex为None，则获取系统所有进程的pid
        if self._pids is not None:
            curr_pids = self._pids
        else:
            curr_pids = self._sys_proc.get_proc_pid_list(self._cmd_regex)

        for pid in curr_pids:
            pid_conn_dict = self._sys_proc.get_proc_pid_net_connections(pid)
            all_conns_dict[pid] = pid_conn_dict
        return all_conns_dict

    async def __refresh_conn(self):
        while self.run_flag:
            all_conns_dict = self._get_conns()

            new_addr_pid_map: Dict[str, int] = {}
            new_traffic_pid_map: Dict[int, List] = {}
            new_traffic_pid_conn_map: Dict[int, Dict[str, List]] = {}
            for pid, conn_list_dict in all_conns_dict.items():
                new_traffic_pid_map[pid] = [0, 0, 0, 0]
                new_traffic_pid_conn_map[pid] = {}
                for conn_key, conn_dict in conn_list_dict.items():
                    new_addr_pid_map[conn_key] = pid
                    new_traffic_pid_conn_map[pid][conn_key] = [0, 0, 0, 0]

            for pid in new_traffic_pid_map.keys():
                if pid in self._traffic_pid_map:
                    new_traffic_pid_map[pid] = copy.deepcopy(self._traffic_pid_map[pid])

            for pid in new_traffic_pid_conn_map.keys():
                if pid in self._traffic_pid_conn_map:
                    for conn_key in new_traffic_pid_conn_map[pid].keys():
                        if conn_key in self._traffic_pid_conn_map[pid]:
                            new_traffic_pid_conn_map[pid][conn_key] = copy.deepcopy(
                                self._traffic_pid_conn_map[pid][conn_key])

            self._addr_pid_map = new_addr_pid_map
            self._traffic_pid_conn_map = new_traffic_pid_conn_map
            self._traffic_pid_map = new_traffic_pid_map

            await asyncio.sleep(self._itv)
            self._call_back(self._traffic_pid_map, self._traffic_pid_conn_map)

    def run(self):
        asyncio.set_event_loop(self._loop)
        self._cap_thread.start()
        # self._loop.create_task(self.__refresh_conn())
        # self._loop.create_task(self._cap_func())
        # print(f' net cap run....')
        # self._loop.run_forever()

        self._loop.run_until_complete(asyncio.gather(
            self.__refresh_conn(),
            self._cap_func()
        ))
        self._loop.close()

    async def _cap_func(self):
        while self.run_flag:
            try:
                packet_tuple: Tuple = self._queue.get(timeout=1)
                await self._handle_packet(packet_tuple)
                await asyncio.sleep(0)
            except Empty:
                await asyncio.sleep(1)

    async def _handle_packet(self, packet_info: Tuple):
        cap_time, src_ip, src_port, dst_ip, dst_port, tcp_len = packet_info
        send_connect_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        direction, pid, conn_key = None, None, None
        if send_connect_key in self._addr_pid_map:
            direction = "send"
            pid = self._addr_pid_map[send_connect_key]
            conn_key = send_connect_key
        else:
            recv_connect_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
            if recv_connect_key in self._addr_pid_map:
                direction = "recv"
                pid = self._addr_pid_map[recv_connect_key]
                conn_key = recv_connect_key

        # 如果同观测的进程不匹配，则直接退出
        if direction is None:
            return
        # print(f'{src_ip}:{src_port} ==> {dst_ip}:{dst_port}, '
        #      f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(cap_time))} {tcp_len}')
        proc_traffic = self._traffic_pid_map[pid]
        conn_traffic = self._traffic_pid_conn_map[pid][conn_key]
        if direction == 'send':
            proc_traffic[0] += 1
            proc_traffic[1] += tcp_len
            conn_traffic[0] += 1
            conn_traffic[1] += tcp_len
        else:
            proc_traffic[2] += 1
            proc_traffic[3] += tcp_len
            conn_traffic[2] += 1
            conn_traffic[3] += tcp_len

    def stop(self) -> None:
        self._cap_thread.stop()
        self.run_flag = False
        self._queue.queue.clear()


class ProcNetStat(object):
    def __init__(self, dev, pids: List[int] = None, cmd_regex=None, interval=1, filter_exp=None):
        self.dev, self.pids, self.cmd_regex, self.interval, self.filter_exp = dev, pids, cmd_regex, interval, filter_exp
        self._traffic_pid_dict: Optional[Dict[int, List[int]]] = None
        self._traffic_pid_conn_dict: Optional[Dict[int, Dict[str, List[int]]]] = None
        self._net_thread = self._activate_stat()

    def _activate_stat(self):
        """
        基于初始化的参数，实现指定网卡的进程流量统计
        Returns:
            内部调用
        """
        loop = asyncio.new_event_loop()

        def handle_call_back(traffic_pid: Dict[int, List[int]], traffic_pid_conn: Dict[int, Dict[str, List[int]]]):
            self._traffic_pid_dict = copy.deepcopy(traffic_pid)
            self._traffic_pid_conn_dict = copy.deepcopy(traffic_pid_conn)

        # 启动监听进程
        net_stat = NetCapStat(dev=self.dev, pids=self.pids, loop=loop, cmd_regex=self.cmd_regex, interval=self.interval,
                              call_back=handle_call_back, filter_exp=self.filter_exp)
        net_stat.start()
        return net_stat

    def join(self):
        self._net_thread.join()

    def stop(self):
        self._net_thread.stop()

    def get_pid_net_traffic(self, pid: int) -> Optional[List[int]]:
        if pid in self._traffic_pid_dict:
            return copy.deepcopy(self._traffic_pid_dict[pid])
        return None

    def get_pid_conn_net_traffic(self, pid: int) -> Optional[Dict[str, List[int]]]:
        if self._traffic_pid_conn_dict is not None and pid in self._traffic_pid_conn_dict:
            pid_conn_traffic: Dict[str, List[int]] = self._traffic_pid_conn_dict[pid]
            return {conn_key: copy.deepcopy(conn_traffic) for conn_key, conn_traffic in pid_conn_traffic.items()}
        return None

    @property
    def all_pid_traffic(self):
        return self._traffic_pid_dict

    @property
    def all_pid_conn_traffic(self):
        return self._traffic_pid_conn_dict
