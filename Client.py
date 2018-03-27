from pydispatch import dispatcher
from utils import OP
from packet import Packet
import rsa
import os
import hashlib
from diffiehellman.diffiehellman import DiffieHellman
from Crypto.Cipher import AES


class Client:

    def __init__(self, node_table):
        self.node_table = node_table
        self.aes_keys = {}
        self.dhke = DiffieHellman()
        # automatically generates private key
        self.dhke.generate_public_key()
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        self.__dh_sharedkey = None
        self.send_ops = {
            OP.CREATE: self.get_create_packet,
            OP.EXTEND: self.get_extend_packet
        }
        # Set once we establish a connect to an entry node
        self.entry_node = None

        # the client is listening to any CREATED messages
        dispatcher.connect(self.handle_created, signal=OP.CREATED,
                           sender=dispatcher.Any)
        dispatcher.connect(self.handle_extended, signal=OP.EXTENDED,
                           sender=dispatcher.Any)

        # Same bug as handle_created for handle_extended.... See handle_created
        dispatcher.connect(self.handle_extended, signal=OP.EXTEND,
                           sender=dispatcher.Any)

    def get_create_packet(self, receivers):
        receiver = self.node_table[receivers[0]]
        msg = self.dh_pub
        enc_msg = rsa.encrypt(msg, receiver.pubkey)
        packet = Packet(src_id="client", op=OP.CREATE,
                        dest=receiver.id, payload=(enc_msg, None))
        return packet

    def send_message(self, receivers, op):
        receivers = receivers.split()
        packet = self.send_ops[op](receivers)
        dispatcher.send(signal=op, sender=self, packet=packet)

    def handle_created(self, packet):
        (other_key, keyHash) = packet.msg
        # Generate the shared key
        self.dhke.generate_shared_secret(other_key)
        shared = self.dhke.shared_key
        mykeyHash = hashlib.sha1(str(shared).encode("utf-8")).hexdigest()

        if mykeyHash == keyHash:  # Only go through if hash matches
            self.__dh_sharedkey = shared
            print(shared)
            self.aes_keys[packet.src] = shared
            self.entry_node = packet.src
            print("Client's entry node is now set to: ", self.entry_node)

    def handle_extended(self, packet):
        (other_key, keyHash) = packet.msg

    # Extend always gets wrapped with everything in the the AES Keys list
    def get_extend_packet(self, receivers):
        msg = "Type:     Extend"
        extend_messages = {}
        for j in range(len(receivers) - 1):
            extend_messages[receivers[j]] = self.aes_encrypt(msg, self.aes_keys[receivers[j]])

        def recursive_extend(recs, node_index):
            if node_index == len(recs) - 1:
                return self.get_create_packet(recs)
            return Packet(src_id="client", op=OP.EXTEND, dest=recs[0],
                          payload=(msg, recursive_extend(recs, node_index + 1)))

        packet = recursive_extend(receivers, 0)
        return packet

    # Encrypts the msg
    def aes_encrypt(self, msg, key):
        obj = AES.new(key[0:32], AES.MODE_CBC, os.urandom(16))
        enc_msg = obj.encrypt(msg)
        return enc_msg
