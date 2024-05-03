from collections import OrderedDict

# pid_stat_fields /proc/$pid/stat
pid_stat_fields = OrderedDict([
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
])

# pid_statm_fields /proc/$pid/statm
pid_statm_fields = OrderedDict([
    ('size', 'total program size (pages)'),
    ('resident', 'size of memory portions (pages)'),
    ('shared', 'number of pages that are shared'),
    ('trs', 'number of pages that are ‘code’'),
    ('lrs', 'number of pages of library'),
    ('drs', 'number of pages of data/stack'),
    ('dt', 'number of dirty pages'),
])

# pid_schedstat_fields /proc/$pid/schedstat
pid_schedstat_fields = OrderedDict([
    ('cpu_time', 'time spend on the cpu'),
    ('wait_time', 'time spend waiting on a run queue'),
    ('slice_time', '# of time slices run on this cpu'),
])

# cpustat_fields /proc/stat中 CPU对应行解析，单位均为jiffies
cpustat_fields = OrderedDict([
    ('cpu_name', 'CPU的编号，如果为cpu则表示为所有CPU的统计；cpuN，则为制定编号的CPU信息'),
    ('user', '系统启动后累计当当前时刻，处于用户态运行时间，不包含nice值为负的进程'),
    ('nice', '系统启动后累计当当前时刻，nice值为负值进程所占用CUP时间处于用户态运行时间'),
    ('system', '系统启动后累计当当前时刻，处于核心态运行时间的CPU时间'),
    ('idle', '系统启动后累计当当前时刻，除IO等待时间以外的启停等待时间'),
    ('io_wait', '# 系统启动后累计当当前时刻，IO等待时间'),
    ('irq', '系统启动后累计当当前时刻，硬中断时间'),
    ('soft_irq', '系统启动后累计当当前时刻，软中断时间'),
    ('steal', '运行在虚拟环境中其他操作系统占用的时间'),
    ('guest', '操作系统运行虚拟CPU占用时间'),
    ('guest_nice', '运行一个带nice值的guest占用时间'),
])

