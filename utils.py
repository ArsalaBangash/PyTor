from enum import Enum
import rsa


class OP(Enum):
    CREATE, CREATED, EXTEND, EXTENDED, RELAY, RELAYED = range(6)

# TODO: Define message (ie packet) structure!


class Packet:

    def __init__(self, op, dest,  payload):
        self.op = None
        self.dest = None
        self.payload = None
        self.__op = op
        self.__dest
        self.__payload = payload[1]
        self.enc_msg = payload[0]

    def decrypt_rsa(self, prikey):
        if (!rsa.decrypt(self.__payload, prikey).startswith("DH_KEY")):
            return False
        self.payload = rsa.decrypt(self.__payload, prikey)
        self.decrypt_packet()
        return True
    
    def decrypt_packet(self):
        self.op = self.__op
        self.dest = self.__dest        
