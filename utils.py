from enum import Enum
import collections


class OP(Enum):
    CREATE, CREATED, EXTEND, EXTENDED, RELAY, RELAYED = range(6)


class HopPair:

    def __init__(self, prev, next):
        self.prev = prev
        self.next = next
