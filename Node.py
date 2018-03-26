from pydispatch import dispatcher
import rsa
from utils import OP
from packet import Packet
from diffiehellman.diffiehellman import DiffieHellman


class Node:
    def __init__(self, id):
        self.id = id
        self.dhke = DiffieHellman(key_length=200)
        self.dhke.generate_public_key()
        self.__dh_sharedkey = None
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        (self.pubkey, self.__privkey) = rsa.newkeys(512)

        # Maps Circuit IDs to previous and next hops
        # Initially, the node will not know the previous and next hops in the circuit
        self.hop_table = {1: (None, None)}
        dispatcher.connect(self.handle_create,
                           signal=OP.CREATE, sender=dispatcher.Any)

    def handle_create(self, packet):
        if packet.dest != self.id:
            return None
        if packet.decrypt_rsa(self.__privkey):
            other_key = int(packet.payload)
            self.__dh_sharedkey = self.dhke.generate_shared_secret(other_key)
        self.hop_table[1] = (packet.src, None)