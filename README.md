
本项目（pypidstat）是基于 [sysstat](https://github.com/sysstat/sysstat) 中pidstat组件和 [nethogs](https://github.com/raboof/nethogs) 两个项目而成。

## 一、功能信息介绍
使用python语言开发，提供进程信息、进程负载和网络负载的接口实现。

### 1.1. 进程信息（ProcessStat）
1. 进程attrs属性信息 
> （comm、cmdline、exe、environ、sessionid、oom_score、uid、gid、owner）

2. stat_info信息（/proc/$pid/stat）

 
    ('pid', 'process id'),
    ('tcomm', 'filename of the executable'),
    ('state', 'state (R is running, S is sleeping, D is sleeping in an uninterruptible wait, '
              'Z is zombie, T is traced or stopped)'),
    ('ppid', 'process id of the parent process'),
    ('pgrp', 'pgrp of the process'),
    ('sid', 'session id'),
    ('tty_nr', 'tty the process uses'),
    ('tty_pgrp', 'pgrp of the tty'),
    ('flags', 'task flags'),
    ('min_flt', 'number of minor faults'),
    ('cmin_flt', 'number of minor faults with child’s'),
    ('maj_flt', 'number of major faults'),
    ('cmaj_flt', 'number of major faults with child’s'),
    ('utime', 'user mode jiffies'),
    ('stime', 'kernel mode jiffies'),
    ('cutime', 'user mode jiffies with child’s'),
    ('cstime', 'kernel mode jiffies with child’s'),
    ('priority', 'priority level'),
    ('nice', 'nice level'),
    ('num_threads', 'number of threads'),
    ('it_real_value', '(obsolete, always 0)'),
    ('start_time', 'time the process started after system boot'),
    ('vsize', 'virtual memory size'),
    ('rss', 'resident set memory size'),
    ('rsslim', 'current limit in bytes on the rss'),
    ('start_code', 'address above which program text can run'),
    ('end_code', 'address below which program text can run'),
    ('start_stack', 'address of the start of the main process stack'),
    ('esp', 'current value of ESP'),
    ('eip', 'current value of EIP'),
    ('pending', 'bitmap of pending signals'),
    ('blocked', 'bitmap of blocked signals'),
    ('sigign', 'bitmap of ignored signals'),
    ('sigcatch', 'bitmap of caught signals'),
    ('0', '(place holder, used to be the wchan address, use /proc/PID/wchan instead)'),
    ('0', '(place holder)'),
    ('0', '(place holder)'),
    ('exit_signal', 'signal to send to parent thread on exit'),
    ('task_cpu', 'which CPU the task is scheduled on'),
    ('rt_priority', 'realtime priority'),
    ('policy', 'scheduling policy (man sched_setscheduler)'),
    ('blkio_ticks', 'time spent waiting for block IO'),
    ('gtime', 'guest time of the task in jiffies'),
    ('cgtime', 'guest time of the task children in jiffies'),
    ('start_data', 'address above which program data+bss is placed'),
    ('end_data', 'address below which program data+bss is placed'),
    ('start_brk', 'address above which program heap can be expanded with brk()'),
    ('arg_start', 'address above which program command line is placed'),
    ('arg_end', 'address below which program command line is placed'),
    ('env_start', 'address above which program environment is placed'),
    ('env_end', 'address below which program environment is placed'),
    ('exit_code', 'the thread’s exit_code in the form reported by the waitpid system call'),

3. io_info 信息


    rchar:  读出的总字节数，read或者pread（）中的长度参数总和（pagecache中统计而来，不代表实际磁盘的读入）
    wchar: 写入的总字节数，write或者pwrite中的长度参数总和
    syscr:  read（）或者pread（）总的调用次数
    syscw: write（）或者pwrite（）总的调用次数
    read_bytes: 实际从磁盘中读取的字节总数   （这里if=/dev/zero 所以没有实际的读入字节数）
    write_bytes: 实际写入到磁盘中的字节总数
    cancelled_write_bytes: 由于截断pagecache导致应该发生而没有发生的写入字节数（可能为负数）

4. statm_info信息


    ('size', 'total program size (pages)'),
    ('resident', 'size of memory portions (pages)'),
    ('shared', 'number of pages that are shared'),
    ('trs', 'number of pages that are ‘code’'),
    ('lrs', 'number of pages of library'),
    ('drs', 'number of pages of data/stack'),
    ('dt', 'number of dirty pages'),

5. schedstat_info信息


    ('cpu_time', 'time spend on the cpu'),
    ('wait_time', 'time spend waiting on a run queue'),
    ('slice_time', '# of time slices run on this cpu'),

6. fd_info 信息


    'fd':  文件的操作fd
    "pid": 进程的PID
    "ctime": 文件打开的事件
    'file': 文件的路径
    'type': 文件类型（regular、socket、anon_inode、other）

7. get_whole_memory 
   

    获取文件的整体内存信息
   
8. set_proc_traffic(proc_net_traffic, proc_net_conn_traffic)


    设置进程的网络负载和网络链接的负载
    proc_net_traffic，负载为四个元素的列表。类别的每个元素分别为[send_packet_cnt/s', send_packet_bytes/s, recv_packet_cnt/s, recv_packet_bytes/s]
    proc_net_conn_traffic，每个链接的负载信息。
        key为网络链接的conn_key, value为负载信息，同进程的四元列表一样

### 1.2. 进程的网络负载信息（ProcNetStat）
因/proc/中不存在进程的网络发送的相关信息，故需要自行抓捕和统计。采用libpcap + pypcap抓包，使用dpkt进行解包。

网络统计，分为基于进程ID和基于进程ID+连接conn_key（src_ip:src_port-dst_ip:dst_port）。统计的traffic为四个元素的数组，分别为(send_packet_cnt/s', send_packet_bytes/s, recv_packet_cnt/s, recv_packet_bytes/s)

## 二、使用示例 

### 2.1. usage
```angular2html
(pypidstat) root@autodl-container-140444a437-916c940b:~/autodl-fs/05projects/pypidstat/pypidstat# python pidstat.py --help
usage: pypidstat [-h] [-v] [-u] [-r] [-w] [-d] [-n] [-l] [-p PIDS]
                 [--comm_regex COMM_REGEX] [--dev DEV] [--ignore]
                 itv count

对于进场信息的统计和展示

positional arguments:
  itv                   设置时间间隔
  count                 设置轮询次数

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -u, --cpu             显示各个进程的cpu使用统计
  -r, --memory          显示各个进程的内存使用统计
  -w, --switch          显示每个进程的上下文切换情况
  -d, --disk            显示各个进程的IO使用情况
  -n, --network         显示各进程的网络情况
  -l, --long            显示命令名和所有参数
  -p PIDS, --pids PIDS  设置进程PID列表，以逗号分割
  --comm_regex COMM_REGEX
                        命令行过滤正则表达式
  --dev DEV             设置网络监听的网卡。如果未设置，则默认设置第一块网卡
  --ignore              过滤自身程序

-----------------------------------------------

```

### 2.2 使用示例
> python pidstat.py --comm_regex .*proxy.* --ignore -u -r -w -d -l 2 10
```angular2html
(pypidstat) root@autodl-container-140444a437-916c940b:~/autodl-fs/05projects/pypidstat/pypidstat# python pidstat.py --comm_regex .*proxy.* --ignore -u -r -w -d -l 2 10
Time                 PID    User    %usr   %sys   %guest %wait  %CPU   CPU_ID  minflt/s majflt/s VSZ      RSS      VmPeak(KB)   %MEM  kB_rd/s  kB_wr/s  kB_cwr/s  iodelay  cswch/s  nvcswch/s Command                                           
2024-05-03 20:10:23  771    root     0.00   0.00   0.00   0.00   0.00     0      0.0      0.0    7.3E+05  17736.0    728956.0    0.00   0.0      0.0       0         0        0         0      proxy -c /init/proxy/proxy.ini                    
2024-05-03 20:10:25  771    root     0.00   0.00   0.00   0.00   0.00     0      0.0      0.0    7.3E+05  17736.0    728956.0    0.00   0.0      0.0       0         0        0         0      proxy -c /init/proxy/proxy.ini                    
2024-05-03 20:10:27  771    root     0.00   0.00   0.00   0.00   0.00     0      0.0      0.0    7.3E+05  17736.0    728956.0    0.00   0.0      0.0       0         0        0         0      proxy -c /init/proxy/proxy.ini                    
2024-05-03 20:10:29  771    root     0.00   0.00   0.00   0.00   0.00     0      0.0      0.0    7.3E+05  17736.0    728956.0    0.00   0.0      0.0       0         0        0         0      proxy -c /init/proxy/proxy.ini
```


    --comm_regex .*proxy.* : 设置过滤的命令正则表达式
    --ignore    ：过滤自身的pid
    -u          ：展示CPU相关信息
    -r          ：展示内存相关信息
    -w          ：展示上下文切换相关信息
    -d          ：展示磁盘读写相关信息
    -l          ：展示命令的完整cmdline
    2 10        ：间隔为2秒，输出次数为10

same to: https://gitee.com/thirsd/pypidstat
