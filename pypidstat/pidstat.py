from typing import Dict, List, Union
import time
import sys
import os
import signal
sys.path.insert(0, os.path.dirname(os.path.abspath(os.path.dirname(os.path.dirname(__file__)))))

from pypidstat.core import ProcessStat, ProcSys
from pypidstat.net import ProcNetStat
from pypidstat.utils import format_float_str

self_pid = os.getpid()


def print_header(args):
    header_str = f"{'Time':<20} {'PID':<6} {'User':<8}"
    if args.cpu:
        header_str += f"{'%usr':<6} {'%sys':<6} {'%guest':<6} {'%wait':<6} {'%CPU':<6} {'CPU_ID':<8}"
    if args.memory:
        header_str += f"{'minflt/s':<8} {'majflt/s':<8} {'VSZ':<8} {'RSS':<8} {'VmPeak(KB)':<12} {'%MEM':<6}"
    if args.disk:
        header_str += f"{'kB_rd/s':<8} {'kB_wr/s':<8} {'kB_cwr/s':<8} {'iodelay':^10}"
    if args.switch:
        header_str += f"{'cswch/s':<8} {'nvcswch/s':<10}"
    if args.network:
        header_str += f"{'s_cnt/s':<8} {'s_byte/s':<10} {'r_cnt/s':<8} {'r_byte/s':<10}"

    header_str += f"{'Command':<50}"
    return header_str


def print_row(prev: ProcessStat, curr: ProcessStat, args, itv):
    row_str = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(curr.curr_timestamp)):<20} {curr.proc_id:<6} " \
              f"{curr.attrs['owner']:<8}"
    if args.cpu:
        c_cpu_loads = curr.get_cpu_loads(prev, itv=itv)
        row_str += f"{format_float_str(c_cpu_loads['%usr'], 6, 2):^6} " \
                   f"{format_float_str(c_cpu_loads['%system'], 6, 2):^6} " \
                   f"{format_float_str(c_cpu_loads['%guest'], 6, 2):^6} " \
                   f"{format_float_str(c_cpu_loads['%wait'], 6, 2):^6} " \
                   f"{format_float_str(c_cpu_loads['%CPU'], 6, 2):^6} {c_cpu_loads['CPU_ID']:^8}"
    if args.memory:
        c_memory_loads = curr.get_mem_loads(prev, itv=itv)
        row_str += f"{format_float_str(c_memory_loads['minflt/s'], 8, 1):^8} " \
                   f"{format_float_str(c_memory_loads['majflt/s'], 8, 1):^8} " \
                   f"{format_float_str(c_memory_loads['vsize'], 8, 1):^8} " \
                   f"{format_float_str(c_memory_loads['rss'], 8, 1):^8} " \
                   f"{format_float_str(c_memory_loads['VmPeak(KB)'], 12, 1):^12} " \
                   f"{format_float_str(c_memory_loads['%MEM'], 6, 2):^6}"
    if args.disk:
        c_disk_loads = curr.get_io_loads(prev, itv=itv)
        row_str += f"{format_float_str(c_disk_loads['kB_rd/s'], 8, 1):^8} " \
                   f"{format_float_str(c_disk_loads['kB_wr/s'], 8, 1):^8} " \
                   f"{format_float_str(c_disk_loads['kB_cwr/s'], 8, 0):^8} " \
                   f"{format_float_str(c_disk_loads['iodelay'], 8, 0):^10}"
    if args.switch:
        c_switch_loads = curr.get_ctx_switch_loads(prev, itv=itv)
        row_str += f"{format_float_str(c_switch_loads['cswch/s'], 8, 0):^8} " \
                   f"{format_float_str(c_switch_loads['nvcswch/s'], 10, 0):^10} "
    if args.network:
        c_network_loads = curr.get_net_loads(prev, itv=itv)
        row_str += f"{format_float_str(c_network_loads['send_packet_cnt/s'], 8, 0):<8} " \
                   f"{format_float_str(c_network_loads['send_packet_bytes/s'], 10, 0):<10} " \
                   f"{format_float_str(c_network_loads['recv_packet_cnt/s'], 8, 0):<8} " \
                   f"{format_float_str(c_network_loads['recv_packet_bytes/s'], 10, 0):<10} "
    if args.long:
        row_str += f"{curr.attrs['cmdline']:<50}"
    else:
        row_str += f"{curr.attrs['comm']:<50}"
    return row_str


def main(args):
    def get_refresh_pids(args):
        all_pids = ProcSys().get_proc_pid_list()
        if args.pids is not None and str(args.pids).strip() != "":
            curr_pids = [int(pid.strip()) for pid in str(args.pids).strip(',') if
                         pid.isdigit() and int(pid.strip()) in all_pids]
        elif args.comm_regex is not None:
            curr_pids = ProcSys().get_proc_pid_list(args.comm_regex)
        elif args.pids is None and args.comm_regex is None:
            curr_pids = all_pids
        else:
            curr_pids = all_pids

        if args.ignore:
            curr_pids = [pid for pid in curr_pids if pid != self_pid]

        return curr_pids

    if args.network:
        # 如果未设置网卡，则默认去第一块网卡
        if args.dev is not None:
            dev = args.dev
        else:
            from pypidstat.net import get_dev_interface
            dev = [dev_name for dev_name, dev_dict in get_dev_interface().items() if dev_name != 'lo'][0]
        # 启动进程网卡的统计线程
        global_proc_net_traffic = ProcNetStat(dev=dev, pids=args.pids, cmd_regex=args.comm_regex, interval=1)
    else:
        global_proc_net_traffic = None

    cnt = args.count if args.count is not None else -1
    itv = args.itv if args.itv is not None else 2

    def signal_handler(sign, frame):
        print('Caught Ctrl+C / SIGINT signal')
        if global_proc_net_traffic is not None:
            global_proc_net_traffic.stop()
            time.sleep(0.5)
            os.kill(os.getpid(), signal.SIGINT)
        exit(0)

    # 处理信号绑定
    for sig in [signal.SIGINT, signal.SIGHUP, signal.SIGTERM, signal.SIGTSTP]:
        # print(sig)
        signal.signal(sig, signal_handler)
    # signal.signal(signal.SIGINT, signal_handler)

    print(print_header(args))
    time.sleep(2)
    stat_keep: List[Union[Dict[int, ProcessStat], None]] = [{}, {}]
    prev = 0
    curr = 1
    while True:
        # 上一个和当前项转换
        curr, prev = 1 - curr, 1 - prev
        # 清理当前项位置的原有值
        if stat_keep[curr] is not None:
            stat_keep[curr].clear()

        # 获取当前进程的最新负载值
        pids = get_refresh_pids(args=args)
        for pid in pids:
            ps_stat = ProcessStat(proc_id=pid)
            ps_stat.init()
            if args.network:
                ps_stat.set_proc_traffic(
                    proc_net_traffic=global_proc_net_traffic.get_pid_net_traffic(pid),
                    proc_net_conn_traffic=global_proc_net_traffic.get_pid_conn_net_traffic(pid)
                )
            stat_keep[curr][pid] = ps_stat

        # 如果上一个记录非空，则可以进行打印负载
        if stat_keep[prev] is not None:
            for pid in stat_keep[curr].keys():
                # 进程ID在Prev保存记录，可以进行打印
                if pid in stat_keep[prev]:
                    curr_pid_stat: ProcessStat = stat_keep[curr][pid]
                    prev_pid_stat: ProcessStat = stat_keep[prev][pid]
                    print(print_row(prev_pid_stat, curr_pid_stat, args, itv=itv))

        if cnt > 0:
            cnt -= 1
        elif cnt == 0:
            break
        time.sleep(itv)


if __name__ == "__main__":
    import argparse

    # 创建一个解析器
    parser = argparse.ArgumentParser(
        prog="pypidstat",  # 程序名，默认为sys.argv[0]
        description="对于进场信息的统计和展示",  # 程序描述
        epilog="-----------------------------------------------"  # 帮助信息底部的文本
    )
    parser.add_argument('itv', type=int, action="store", help="设置时间间隔")
    parser.add_argument('count', type=int, action="store", help="设置轮询次数")
    parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
    parser.add_argument('-u', "--cpu", action="store_true", help="显示各个进程的cpu使用统计", default=False)
    parser.add_argument('-r', "--memory", action="store_true", help="显示各个进程的内存使用统计", default=False)
    parser.add_argument('-w', "--switch", action="store_true", help="显示每个进程的上下文切换情况", default=False)
    parser.add_argument('-d', "--disk", action="store_true", help="显示各个进程的IO使用情况", default=False)
    parser.add_argument('-n', "--network", action="store_true", help="显示各进程的网络情况", default=False)
    parser.add_argument('-l', "--long", action="store_true", help="显示命令名和所有参数", default=False)
    parser.add_argument('-p', "--pids", type=str, help="设置进程PID列表，以逗号分割", default=None)
    parser.add_argument("--comm_regex", type=str, help="命令行过滤正则表达式")
    parser.add_argument("--dev", type=str, help="设置网络监听的网卡。如果未设置，则默认设置第一块网卡")
    parser.add_argument("--ignore", action="store_true", help="过滤自身程序")

    i_args = parser.parse_args()

    main(i_args)
