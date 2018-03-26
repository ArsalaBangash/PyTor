from pydispatch import dispatcher
import hashlib
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

        self.send_ops = {
            OP.CREATED: self.get_created_messsage,
            OP.EXTENDED: self.get_extended_message
        }
        # Maps Circuit IDs to previous and next hops
        # Initially, the node will not know the previous and next hops in the circuit
        #Table key is (Previous, Next)
        self.hop_table = {1: (None, None)}
        dispatcher.connect(self.handle_extend, signal=OP.EXTEND, sender=dispatcher.Any)
        dispatcher.connect(self.handle_create,
                           signal=OP.CREATE, sender=dispatcher.Any)



    def handle_extend(self, packet):
        if packet.dest != self.id:
            return None
        if packet.decrypt_aes(self.__dh_sharedkey) == "Extend":
            #We need to do some sort of creation
            #Need to wait for created first
            #Then return with extended
            return
        #Else we are not the creators pass it on
        #Do i just keep dispatching? Non-deterministic handling.
        self.send_message(self.hop_table.get(1)[1], OP.EXTEND)

    def handle_create(self, packet):
        if packet.dest != self.id:
            return None
        if not packet.decrypt_rsa(self.__privkey):
            return
        other_key = int(packet.payload)
        self.__dh_sharedkey = self.dhke.generate_shared_secret(other_key)
        self.hop_table[1] = (packet.src, None)
        # Respond back with a created message
        self.send_message(self.hop_table.get(1)[0], OP.CREATED)

    def send_message(self, receiver, op):
        packet = self.send_ops[op](receiver)
        dispatcher.send(signal=op, sender=self, packet=packet)
        print("{} sent a CREATED message back to the client".format(self.id))

    def get_created_messsage(self, receiver):
        keyHash =  hashlib.sha1(str(self.__dh_sharedkey).encode("utf-8")).hexdigest()
        msg = (self.dhke.public_key, keyHash)
        packet = Packet(src_id=self.id, op=OP.CREATED, dest=receiver, payload=(msg, None))
        return packet

    def get_extended_message(self, receiver):
        pass
