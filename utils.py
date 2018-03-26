from enum import Enum
import rsa


class OP(Enum):
    CREATE, CREATED, EXTEND, EXTENDED, RELAY, RELAYED = range(6)
