import glob
import os
import functools
import re
from pypidstat.base.fields import pid_stat_fields, pid_statm_fields, pid_schedstat_fields
from pypidstat import TCPConnectStatus
from pypidstat.utils import get_all_users, page_to_kb, parse_kv_txt, get_ip_port_by_addr, get_clk_tick
from typing import AnyStr, Dict, List, Union
from pypidstat.base.types import BaseModel


class ProcSys(BaseModel):
    def __init__(self, base_dir: str = "/proc/"):
        self.base_proc_dir = base_dir

    def _read_file(self, path) -> AnyStr:
        with open(path, 'r') as f:
            return f.read().strip()

    def get_proc_pid_stat(self, pid: int) -> Dict:
        """
        根据进程ID获取进程的/proc/$pid/stat的信息，解析后返回字典类型
        Args:
            pid: 进程的PID

        Returns:
            返回stat文件解析后的结果
        """
        pid_stat_path = os.path.join(self.base_proc_dir, str(pid), 'stat')
        stat_txt = self._read_file(pid_stat_path)
        stat_fields = pid_stat_fields.keys()

        # 解析stat_txt，因命令存在空格的原因，需要单独处理
        # 2894 (sshd) S 1160 2894 2894 0 -1 1077944576 1901 1516 .................
        spit_fields = [pid]
        comm_start = stat_txt.find("(")
        comm_end = stat_txt.find(")")
        comm = stat_txt[comm_start + 1: comm_end]
        spit_fields.append(comm)
        # 剩余的字段进行拆分
        spit_fields.extend(stat_txt[comm_end + 1:].split())

        stat_result_dict = {k: v for k, v in zip(stat_fields, spit_fields)}

        # 统一vsz和rss的格式KB
        stat_result_dict["vsize"] = float(stat_result_dict["vsize"]) / 1024
        stat_result_dict["rss"] = float(page_to_kb(int(stat_result_dict["rss"])))
        for key_to_int in ['utime', 'stime', 'gtime', 'min_flt', 'cmin_flt', 'maj_flt', 'cmaj_flt', 'rss', 'vsize']:
            stat_result_dict[key_to_int] = int(stat_result_dict[key_to_int])

        return stat_result_dict

    def get_proc_pid_io(self, pid: int) -> Dict:
        """
        根据用户进程，返回进程的IO读写字典项，主要包含rchar、wchar、syscr、syscw、read_bytes、write_bytes、cancelled_write_bytes
        Args:
            pid: 进程ID

        Returns:
            返回进程的IO磁盘信息。
        """
        pid_io_path = os.path.join(self.base_proc_dir, str(pid), 'io')
        txt = self._read_file(pid_io_path)
        io_dict = parse_kv_txt(txt, ':')

        for key_to_int in io_dict.keys():
            io_dict[key_to_int] = int(io_dict[key_to_int])

        return io_dict

    def get_proc_user(self, pid: int) -> Dict:
        """
        根据进程ID，返回进程的用户名
        Args:
            pid: 用户进程

        Returns:
            返回进程的用户信息。uid，name，gid
        """
        # 获取进程的用户信息
        pid_loginuid_path = os.path.join(self.base_proc_dir, str(pid), 'loginuid')
        login_uid = self._read_file(pid_loginuid_path)
        if login_uid == "4294967295":
            login_uid = "0"

        # 根据用户的login_uid补充进程用户信息
        match_users = [user for user in get_all_users() if str(user['uid']) == login_uid]
        proc_user_dict = {}
        if len(match_users) == 0:
            proc_user_dict['uid'] = login_uid
            proc_user_dict['gid'], proc_user_dict['owner'] = None, None
        else:
            proc_user_dict['uid'] = login_uid
            proc_user_dict['gid'], proc_user_dict['owner'] = match_users[0]['gid'], match_users[0]['name']
        return proc_user_dict

    def get_proc_pid_attrs(self, pid: int) -> Dict:
        """
        根据用户的进程获取进程相关信息。包含进程的启动命令、执行程序、环境变量、会话ID、OOM的评值
        Args:
            pid: 进程ID

        Returns:
            返回指定进程的基本属性信息
        """
        attrs = {
            'comm': self._read_file(os.path.join(self.base_proc_dir, str(pid), 'comm')),
            'cmdline': self._read_file(os.path.join(self.base_proc_dir, str(pid), 'cmdline')).replace('\0', ' '),
            'exe': os.readlink(os.path.join(self.base_proc_dir, str(pid), 'exe')),
            'environ': self._read_file(os.path.join(self.base_proc_dir, str(pid), 'environ')),
            'sessionid': self._read_file(os.path.join(self.base_proc_dir, str(pid), 'sessionid')),
            'oom_score': self._read_file(os.path.join(self.base_proc_dir, str(pid), 'oom_score')),
        }
        return attrs

    def get_proc_pid_statm(self, pid: int) -> Dict:
        """
        读取/proc/$pid/statm，获取进程的statm信息，并解析为字典。
        内容示例：40532 583 397 24 0 296 0
        size: total program size (pages)
        resident: size of memory portions (pages)
        shared: number of pages that are shared
        trs: number of pages that are ‘code’
        lrs: number of pages of library
        drs: number of pages of data/stack
        dt: number of dirty pages

        Returns:
            返回进程的statm，解析内存的字典项
        """
        pid_statm_path = os.path.join(self.base_proc_dir, str(pid), 'statm')
        statm_txt = self._read_file(pid_statm_path)
        statm_fields = pid_statm_fields.keys()

        # 解析statm_txt，因命令存在空格的原因，需要单独处理
        # 40532 583 397 24 0 296 0
        statm_result_dict = {k: v for k, v in zip(statm_fields, statm_txt.split())}

        return statm_result_dict

    def get_proc_pid_schedstat(self, pid: int) -> Dict:
        """
        根据PID，读取/proc/pid/schedstat，并解析数据返回各字段的字典
        文件的形式为：# 46652635911 155863134 16148
          first: time spend on the cpu (in nanoseconds)
          second: time spend waiting on a run queue (in nanoseconds)
          third: # of time slices run on this cpu

        Args:
            pid: 进程的PID

        Returns:
            返回解析schedstat的字典
        """

        pid_schedstat_path = os.path.join(self.base_proc_dir, str(pid), 'schedstat')
        schedstat_txt = self._read_file(pid_schedstat_path)
        schedstat_fields = pid_schedstat_fields.keys()

        # 解析schedstat_txt
        result_dict = {k: v for k, v in zip(schedstat_fields, schedstat_txt.split())}
        if 'wait_time' in result_dict:
            # onvert ns to jiffies
            result_dict['wait_time'] = (float(result_dict['wait_time']) / 1e9) * get_clk_tick()

        return result_dict

    def get_proc_pid_status(self, pid: int) -> Dict:
        """
        读取/proc/$pid/status，获取进程的status信息，并解析为字典
        Returns:
            返回进程的status解析字典项
        """
        pid_status_path = os.path.join(self.base_proc_dir, str(pid), 'status')
        txt = self._read_file(pid_status_path)
        status_dict = parse_kv_txt(txt, ':')

        status_dict = {k: v if not str(v).endswith("kB") else str(v).replace('kB', '').strip() for k, v in
                       status_dict.items()}
        for key_to_int in ['voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches']:
            status_dict[key_to_int] = int(status_dict[key_to_int])

        return status_dict

    def get_proc_pid_fds(self, pid: int) -> Dict:
        """
        根据进程PID返回打开的文件列表
        Args:
            pid: 进程PID

        Returns:
            返回进程相关的打开文件字典，KEY为fd，Value为文件的描述信息
        """
        fds = os.listdir(os.path.join(self.base_proc_dir, str(pid), 'fd'))
        pid_fds_info = {}
        for f in fds:
            try:
                link = os.readlink(os.path.join(self.base_proc_dir, str(pid), 'fd', f))
            except Exception:
                continue
            else:
                ctime = os.stat(os.path.join(self.base_proc_dir, str(pid), 'fdinfo', f)).st_ctime
                pid_fd_info = {
                    'fd': f, "pid": pid, "ctime": ctime, 'file': link,
                }

                if link.startswith('/') and os.path.isfile(link):
                    pid_fd_info['type'] = 'regular'
                elif link.startswith('socket:'):
                    pid_fd_info['type'] = 'socket'
                    inode = int(link[8:-1])
                    pid_fd_info['inode'] = inode
                elif link.startswith('anon_inode'):
                    pid_fd_info['type'] = 'anon_inode'
                else:
                    pid_fd_info['type'] = 'other'

                pid_fds_info[f] = pid_fd_info
        return pid_fds_info

    def get_proc_net_tcp(self) -> Dict[str, Dict]:
        """
        读取/proc/net/tcp，获取主机中所有的网络连接信息，
        Returns:
            返回进程的列表
        """
        file_path = os.path.join(self.base_proc_dir, 'net/tcp')
        txt = self._read_file(file_path)
        global_tcp_connection = {}
        for line in txt.splitlines()[1:]:
            items = line.split()
            local_ip, local_port = get_ip_port_by_addr(items[1])
            remote_ip, remote_port = get_ip_port_by_addr(items[2])
            connect_key = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"
            status = TCPConnectStatus(int(items[3], 16)).name  # 连接状态
            tx_queue, rx_queue = (int(q, 16) for q in
                                  items[4].split(':'))  # 发送队列中数据长度和接收队列（ESTABLISHED表示接收队列长度，LISTEN 已经完成连接队列的长度）
            retry_send_cnt = int(items[6])  # 超时重传次数
            uid = int(items[7])  # 用户ID
            inode = int(items[9])

            conn_info = {
                "local_ip": local_ip, "local_port": local_port, "remote_ip": remote_ip, "remote_port": remote_port,
                "status": status, "tx_queue": tx_queue, "rx_queue": rx_queue, "retry_send_cnt": retry_send_cnt,
                "uid": uid, "inode": inode, 'connect_key': connect_key,
            }

            global_tcp_connection[connect_key] = conn_info
        return global_tcp_connection

    def get_proc_uptime(self) -> Dict[str, float]:
        """
        读取/proc/uptime的文件，并解析为字典项
        Returns:
            返回/proc/uptime文件的解析字典，主要为sys_run_time_seconds和sys_idle_time_seconds
        """
        uptime_path = os.path.join(self.base_proc_dir, 'uptime')
        txt = self._read_file(uptime_path)
        sys_run_time_seconds, sys_idle_time_seconds = txt.split(" ")[:2]
        uptime__dict = {
            "sys_run_time_seconds": sys_run_time_seconds,
            "sys_idle_time_seconds": sys_idle_time_seconds,
        }
        return uptime__dict

    def get_proc_meminfo(self) -> Dict[AnyStr, AnyStr]:
        """
        读取/proc/meminfo的文件，并解析为字典项
        Returns:
            返回/proc/meminfo解析的字典项。字典key为配置项，value为配置值
        """
        meminfo_path = os.path.join(self.base_proc_dir, 'meminfo')
        txt = self._read_file(meminfo_path)
        mem_info_dict = parse_kv_txt(txt, ':')

        mem_info_dict = {k.strip(): v.replace(' kB', '').strip() for k, v in mem_info_dict.items()}

        return mem_info_dict

    @functools.lru_cache(maxsize=2)
    def get_proc_cpuinfo(self) -> List[Dict]:
        """
        读取/proc/cpuinfo的文件，并解析为字典项
        Returns:
            返回/proc/cpuinfo解析的字典项。列表为每个CPU的信息，CPU信息为字典
        """
        cpuinfo_path = os.path.join(self.base_proc_dir, 'cpuinfo')
        txt = self._read_file(cpuinfo_path)

        cpuinfo_list = []
        for process_txt in txt.split('\n\n'):
            if process_txt.strip() == "":
                continue

            cpu_dict = parse_kv_txt(process_txt, ':')
            cpuinfo_list.append(cpu_dict)

        return cpuinfo_list

    def get_proc_stat(self) -> Dict[str, Union[str, Dict]]:
        """
        读取/proc/stat的文件，并解析为字典项
        Returns:
            返回/proc/stat解析的字典项
        """
        cpustat_path = os.path.join(self.base_proc_dir, 'stat')
        txt = self._read_file(cpustat_path)
        lines = txt.splitlines()

        cpustat_dict = {}

        # 处理CPU的记录
        cpustat_fields = pid_stat_fields.keys()
        for cpu_txt in [line for line in lines if str(line).startswith('cpu')]:
            cpu_dict = {k: v for k, v in zip(cpustat_fields, cpu_txt.split())}
            cpustat_dict[cpu_dict['cpu_name']] = cpu_dict

        # 处理关注项的值
        keys = ['ctxt', 'btime', 'processes', 'procs_running', 'procs_blocked']
        key_lines = [line for line in lines for key in keys if str(line).startswith(key)]
        key_line_text = '\n'.join(key_lines)
        key_value_dict = parse_kv_txt(key_line_text, None)
        cpustat_dict.update(key_value_dict)

        return cpustat_dict

    def get_proc_pid_list(self, cmd_regex=None) -> List[int]:
        """
        根据cmd_regex正则表达式，返回匹配进程cmdline启动命令行的进程ID列表。如果cmd_regex为None，则返回所有进程PID
        Args:
            cmd_regex: 需要匹配cmdline的正则表达式

        Returns:
            匹配的进程PID的列表
        """
        regex = re.compile(cmd_regex) if cmd_regex is not None else None
        match_exp_path = os.path.join(self.base_proc_dir, '*', 'cmdline')
        files = glob.glob(match_exp_path)

        match_pids: List[int] = []
        for file in files:
            pid = file.split('/')[-2]
            if not pid.isdigit():
                continue
            pid = int(pid)
            if cmd_regex is None:
                match_pids.append(pid)
            else:
                pid_cmdline = self._read_file(file)
                if regex.match(pid_cmdline):
                    match_pids.append(pid)
        return match_pids

    def get_proc_pid_net_connections(self, pid: int) -> Dict[str, Dict]:
        """
        根据进程PID，获取进程相关的网络连接
        Args:
            pid: 进程PID

        Returns:
            返回进程的网络连接的字典列表。key为connect_key
        """
        global_tcp_conns = {conn['inode']: conn for conn in self.get_proc_net_tcp().values()}
        pid_tcp_fds = self.get_proc_pid_fds(pid)

        inode_map_dict = {fd_info['inode']: fd_info for fd_info in pid_tcp_fds.values()
                          if 'inode' in fd_info and fd_info['type'] == 'socket'}

        pid_tcp_connections = {}
        for inode in inode_map_dict.keys():
            if inode in global_tcp_conns:
                if global_tcp_conns[inode]['status'] == "ESTABLISHED":
                    conn_key = global_tcp_conns[inode]['connect_key']
                    pid_tcp_connections[conn_key] = global_tcp_conns[inode]

        return pid_tcp_connections
