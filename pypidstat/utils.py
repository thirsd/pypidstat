import functools
import os
import pwd
from typing import Union
import math


@functools.lru_cache(maxsize=2)
def get_all_users():
    user_list = [{'name': user.pw_name, 'uid': user.pw_uid, 'gid': user.pw_gid} for user in pwd.getpwall()]
    return user_list


@functools.lru_cache(maxsize=2)
def get_page_size() -> int:
    return int(os.sysconf("SC_PAGE_SIZE"))


@functools.lru_cache(maxsize=10)
def page_to_kb(page_num: int):
    # 将页数转换为KB
    return page_num * get_page_size() / 1024


@functools.lru_cache(maxsize=2)
def get_clk_tick():
    return os.sysconf("SC_CLK_TCK")


def parse_kv_txt(txt: str, sep: Union[str, None] = ':'):
    kv_dict = {}
    for line in txt.splitlines():
        if sep is None:
            key, value = line.split()[:2]
        else:
            key, value = line.split(sep)[:2]
        key, value = key.strip(), value.strip()
        kv_dict[key] = value
    return kv_dict


def get_ip_port_by_addr(addr):
    ip, port = addr.split(':', 2)
    ip = '.'.join([str(int(ip[i:i + 2], 16)) for i in range(0, len(ip), 2)][::-1])
    port = int(port, 16)
    return ip, port


def format_float_str(f: float, width: int = 6, precision: int = 1):
    if isinstance(f, int) or isinstance(f, str):
        f = float(f)
    mod_len = width - precision - 2
    if f <= math.pow(10, mod_len):
        return f"{f:<.{precision}f}"
    else:
        return f"{f:<.{precision}E}"
