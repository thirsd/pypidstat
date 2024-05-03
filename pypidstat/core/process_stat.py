from typing import Union, Dict, List, Optional
import copy
import time
from pypidstat.base.proc_sys import ProcSys
from pypidstat.base.types import BaseModel
from pypidstat.utils import get_clk_tick


def SP_VALUE(prev: float, curr: float, itv: float) -> float:
    # 计算两个差值及转换为百分比
    return float(curr - prev) / itv * 100


def S_VALUE(prev: float, curr: float, itv: float) -> float:
    # 计算两个差值，并除以间隔
    return float(curr - prev) / itv


class ProcessStat(BaseModel):
    def __init__(self, proc_id: int,):
        self.curr_timestamp: float = None

        self.proc_id: int = proc_id
        self.sys = ProcSys()

        self.base_proc_dir = f"/proc/{self.proc_id}"
        self.attrs: Union[Dict, None] = None
        self.mem_loads: Union[Dict, None] = None
        self.net_loads: Union[Dict, None] = None
        self.io_loads: Union[Dict, None] = None

        self.io_info: Union[Dict, None] = None
        self.statm_info: Union[Dict, None] = None
        self.stat_info: Union[Dict, None] = None
        self.status_info: Union[Dict, None] = None
        self.schedstat_info: Union[Dict, None] = None
        self.fd_info: Union[Dict, None] = {}
        self.is_init = False

        self._proc_net_traffic = None
        self._proc_net_conn_traffic = None

        self.whole_stat = {}

    def init(self):
        self.curr_timestamp = time.time()
        self.attrs = self.sys.get_proc_pid_attrs(self.proc_id)
        self.attrs.update(self.sys.get_proc_user(self.proc_id))
        self.whole_stat.update(self.attrs)

        self.stat_info = self.sys.get_proc_pid_stat(self.proc_id)
        self.io_info = self.sys.get_proc_pid_io(self.proc_id)
        self.statm_info = self.sys.get_proc_pid_statm(self.proc_id)
        self.status_info = self.sys.get_proc_pid_status(self.proc_id)
        self.schedstat_info = self.sys.get_proc_pid_schedstat(self.proc_id)
        self.fd_info = self.sys.get_proc_pid_fds(self.proc_id)

        self.is_init = True

    def get_whole_memory(self) -> float:
        # 返回：整个主机的内存（KB）
        if not self.is_init: self.init()
        return float(self.sys.get_proc_meminfo()['MemTotal'])

    def get_cpu_loads(self, prev: 'ProcessStat' = None, itv: float = 1) -> Dict:
        if not self.is_init: self.init()
        cpu_loads = {'CPU_ID': self.stat_info['task_cpu'], 'threads_num': self.stat_info['num_threads']}
        if prev is None:
            clk_tick = get_clk_tick()
            pid_utime_sec: float = float(self.stat_info['utime']) / clk_tick
            pid_stime_sec: float = float(self.stat_info['stime']) / clk_tick
            pid_start_time_sec: float = float(self.stat_info['start_time']) / clk_tick

            sys_uptime_sec = float(self.sys.get_proc_uptime()['sys_run_time_seconds'])

            # 公式： pid_usage_sec/elapsed_sec = (utime + stime)/(uptime_sec - pid_start_time)
            proc_usage = (pid_utime_sec + pid_stime_sec) / (sys_uptime_sec - pid_start_time_sec)
            cpu_loads['%CPU'] = proc_usage
        else:
            cpu_loads['%usr'] = SP_VALUE(prev.stat_info['utime'] - prev.stat_info['gtime'],
                                          self.stat_info['utime'] - self.stat_info['gtime'], get_clk_tick() * itv)
            cpu_loads['%system'] = SP_VALUE(prev.stat_info['stime'], self.stat_info['stime'], get_clk_tick() * itv)
            cpu_loads['%guest'] = SP_VALUE(prev.stat_info['gtime'], self.stat_info['gtime'], get_clk_tick() * itv)
            cpu_loads['%wait'] = SP_VALUE(prev.schedstat_info['wait_time'], self.schedstat_info['wait_time'], get_clk_tick() * itv)
            cpu_loads['%CPU'] = SP_VALUE(prev.stat_info['utime'] + prev.stat_info['stime'],
                                          self.stat_info['utime'] + self.stat_info['stime'], get_clk_tick() * itv)
        return cpu_loads

    def get_mem_loads(self, prev: 'ProcessStat' = None, itv: int = 1) -> Dict:
        if not self.is_init: self.init()
        mem_loads = {'vsize': self.stat_info['vsize'], 'rss': self.stat_info['rss'],
                     'VmPeak(KB)': self.status_info['VmPeak']}

        if prev is not None:
            mem_loads['minflt/s'] = S_VALUE(prev.stat_info['min_flt'], self.stat_info['min_flt'], itv)
            mem_loads['majflt/s'] = S_VALUE(prev.stat_info['maj_flt'], self.stat_info['maj_flt'], itv)
            mem_loads['%MEM'] = SP_VALUE(0, self.stat_info['rss'], self.get_whole_memory())

        return mem_loads

    def get_io_loads(self, prev: 'ProcessStat' = None, itv: int = 1) -> Dict:
        if not self.is_init: self.init()
        io_loads = {'iodelay': self.stat_info['blkio_ticks']}

        if prev is not None:
            io_loads['kB_rd/s'] = S_VALUE(prev.io_info['read_bytes'], self.io_info['read_bytes'], itv) / 1024
            io_loads['kB_wr/s'] = S_VALUE(prev.io_info['write_bytes'], self.io_info['write_bytes'], itv) / 1024
            io_loads['kB_cwr/s'] = S_VALUE(prev.io_info['cancelled_write_bytes'], self.io_info['cancelled_write_bytes'], itv) / 1024
            io_loads['syscr/s'] = S_VALUE(prev.io_info['syscr'], self.io_info['syscr'], itv)
            io_loads['syscw/s'] = S_VALUE(prev.io_info['syscw'], self.io_info['syscw'], itv)

        return io_loads

    def get_ctx_switch_loads(self, prev: 'ProcessStat' = None, itv: int = 1) -> Dict:
        if not self.is_init: self.init()
        ctx_switch_loads = {}

        if prev is not None:
            ctx_switch_loads['cswch/s'] = S_VALUE(prev.status_info['voluntary_ctxt_switches'],
                                                  self.status_info['voluntary_ctxt_switches'], itv)
            ctx_switch_loads['nvcswch/s'] = S_VALUE(prev.status_info['nonvoluntary_ctxt_switches'],
                                                    self.status_info['nonvoluntary_ctxt_switches'], itv)

        return ctx_switch_loads

    def get_stack_loads(self, prev: 'ProcessStat' = None, itv: int = 1) -> Dict:
        if not self.is_init: self.init()
        stack_loads = {key: self.status_info[key]
                       for key in ['VmHWM', 'RssAnon', 'VmPeak', 'RssFile', 'RssShmem', 'VmData', 'VmStk', 'VmExe', 'VmLib', 'VmSwap']}
        stack_loads['RSSPeak'] = stack_loads['VmHWM']
        stack_loads['VSZPeak'] = stack_loads['VmPeak']

        return stack_loads

    def get_fd_net_count(self) -> int:
        return len(self.fd_info)

    def get_fd_net_info(self) -> int:
        return len(self.fd_info)

    def get_net_loads(self, prev: 'ProcessStat' = None, itv: int = 1) -> Optional[Dict]:
        if prev is None:
            return None

        if self._proc_net_traffic is None or prev._proc_net_traffic is None:
            return None

        net_loads = {
            'send_packet_cnt/s': S_VALUE(prev._proc_net_traffic[0], self._proc_net_traffic[0], itv),
            'send_packet_bytes/s': S_VALUE(prev._proc_net_traffic[1], self._proc_net_traffic[1], itv),
            'recv_packet_cnt/s': S_VALUE(prev._proc_net_traffic[2], self._proc_net_traffic[2], itv),
            'recv_packet_bytes/s': S_VALUE(prev._proc_net_traffic[3], self._proc_net_traffic[3], itv)
        }
        return net_loads

    def get_net_conn_loads(self, prev: 'ProcessStat' = None, itv: int = 1) -> Optional[Dict]:
        if prev is None:
            return None

        if self._proc_net_conn_traffic is None or prev._proc_net_conn_traffic is None:
            return None

        net_conn_loads: Dict[str, Dict[str, float]] = {}
        for conn_key in self._proc_net_conn_traffic:
            if conn_key in prev._proc_net_conn_traffic:
                net_conn_traffic = {
                    'send_packet_cnt/s': S_VALUE(prev._proc_net_conn_traffic[0], self._proc_net_conn_traffic[0], itv),
                    'send_packet_bytes/s': S_VALUE(prev._proc_net_conn_traffic[1], self._proc_net_conn_traffic[1], itv),
                    'recv_packet_cnt/s': S_VALUE(prev._proc_net_conn_traffic[2], self._proc_net_conn_traffic[2], itv),
                    'recv_packet_bytes/s': S_VALUE(prev._proc_net_conn_traffic[3], self._proc_net_conn_traffic[3], itv)
                }
                net_conn_loads[conn_key] = net_conn_traffic

        return net_conn_loads

    def set_proc_traffic(self, proc_net_traffic: [List[int]], proc_net_conn_traffic: Dict[str, List[int]]):
        self._proc_net_traffic = proc_net_traffic
        self._proc_net_conn_traffic = proc_net_conn_traffic
