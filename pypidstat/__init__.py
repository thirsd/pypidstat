from enum import Enum


class TCPConnectStatus(Enum):
    ESTABLISHED = 1
    SYN_SEND = 2
    SYN_RECV = 3
    FIN_WAIT = 4
    FIN_WAIT2 = 5
    TIME_WAIT = 6
    CLOSE = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    LISTEN = 10
    CLOSING = 11