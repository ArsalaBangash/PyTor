from diffiehellman.diffiehellman import DiffieHellman
from pydispatch import dispatcher
import rsa
from utils import OP
from utols import Packet


class Node:
    DHKE = None
    (pubkey, privkey) = (None, None)  # RSA keys

    def __init__(self, id):
        self.id = id
        self.__dh = DiffieHellman()
        self.__dh_sharedkey = None
        (self.pubkey, self.__privkey) = rsa.newkeys(512)
        dispatcher.connect(self.handle_create,
                           signal=OP.CREATE, sender=dispatcher.Any)

    def handle_create(self, packet):
        if packet.decrypt_rsa():
            self.__dh_sharedkey = self.__dh.generate_shared_secret(packet.payload[6:])
    

    def send_created(self):


    def send_message(self, receiver, op):
        packet = self.send_ops[op](receiver)
        dispatcher.send(signal=op, sender=self, packet)
        
