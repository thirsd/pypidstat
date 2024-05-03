# ！/usr/bin/env python
# -*- coding: UTF-8 -*-
"""
@Project: pypidstat
@File: dev
@Author: thirsd@sina.com
@Date: 2024/5/3 11:40
"""
import socket
import fcntl
import struct
import array
import sys
from typing import Dict


def all_interfaces() -> Dict[str, Dict]:
    is_64bits = sys.maxsize > 2 ** 32
    struct_size = 40 if is_64bits else 32
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8  # initial value
    while True:
        _bytes = max_possible * struct_size
        names = array.array('B')
        for i in range(0, _bytes):
            names.append(0)
        out_bytes = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912,  # SIOCGIFCONF
            struct.pack('iL', _bytes, names.buffer_info()[0])
        ))[0]
        if out_bytes == _bytes:
            max_possible *= 2
        else:
            break
    name_str = names.tostring()
    ifaces = {}
    for i in range(0, out_bytes, struct_size):
        iface_name = bytes.decode(name_str[i:i + 16]).split('\0', 1)[0]
        # iface_addr = socket.inet_ntoa(name_str[i + 20:i + 24])

        bytes_iface_name = iface_name.encode()

        ip = socket.inet_ntoa(
            fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', bytes_iface_name))[20:24])  # SIOCGIFADDR
        netmask = socket.inet_ntoa(
            fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', bytes_iface_name))[20:24])  # SIOCGIFNETMASK
        broadcast = socket.inet_ntoa(
            fcntl.ioctl(s.fileno(), 0x8919, struct.pack('256s', bytes_iface_name))[20:24])  # SIOCGIFBRDADDR
        hwaddr = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', bytes_iface_name))[18:24].hex()
        hwaddr = ':'.join([hwaddr[i:i + 2] for i in range(0, len(hwaddr), 2)])

        ifaces[iface_name] = {'name': iface_name, 'hwaddr': hwaddr, 'addr': ip, 'netmask': netmask,
                              'broadcast': broadcast}

    return ifaces
