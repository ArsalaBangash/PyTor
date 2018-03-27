from pydispatch import dispatcher
import hashlib
import rsa
from utils import OP, HopPair
from packet import Packet
from diffiehellman.diffiehellman import DiffieHellman
from Crypto.Cipher import AES


class Node:
    def __init__(self, id):
        self.id = id
        self.dhke = DiffieHellman(key_length=200)
        self.dhke.generate_public_key()
        self.__dh_sharedkey = None
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        (self.pubkey, self.__privkey) = rsa.newkeys(512)

        self.send_ops = {
            OP.CREATED: self.get_created_packet,
            OP.EXTENDED: self.get_extended_message
        }
        # Maps Circuit IDs to previous and next hops
        # Initially, the node will not know the previous and next hops in the circuit
        # Table key is (Previous, Next)
        self.hop_table = {1: HopPair(prev=None, next=None)}
        dispatcher.connect(self.handle_extend, signal=OP.EXTEND, sender=dispatcher.Any)
        dispatcher.connect(self.handle_create,
                           signal=OP.CREATE, sender=dispatcher.Any)
        dispatcher.connect(self.handle_created, signal=OP.CREATED, sender=dispatcher.Any)

    def handle_extend(self, packet):
        if packet.dest != self.id:
            return None
        if packet.decrypt_aes(self.__dh_sharedkey):
            print("Decryption successful")
            forward_packet = packet.payload
            self.hop_table[1].next = packet.dest
            dispatcher.send(signal=forward_packet.op, sender=self, packet=forward_packet)

    def handle_create(self, packet):
        if packet.dest != self.id:
            return None
        if not packet.decrypt_rsa(self.__privkey):
            return
        other_key = int(packet.payload)
        self.dhke.generate_shared_secret(other_key)
        self.__dh_sharedkey = self.dhke.shared_key
        self.hop_table[1].prev = packet.src
        # Respond back with a created message
        self.send_packet(self.hop_table[1].prev, OP.CREATED)

    def send_packet(self, receiver, op, payload=None):
        packet = self.send_ops[op](receiver, payload)
        dispatcher.send(signal=op, sender=self, packet=packet)
        print("{} sent a {} message back to the client".format(self.id, op))

    def get_created_packet(self, receiver, payload=None):
        key_hash = hashlib.sha1(
            str(self.__dh_sharedkey).encode("utf-8")).hexdigest()
        msg = (self.dhke.public_key, key_hash)
        packet = Packet(src_id=self.id, op=OP.CREATED,
                        dest=receiver, payload=(msg, None))
        return packet

    def get_extended_message(self, receiver, payload):
        packet = Packet(self.id, OP.EXTENDED, receiver, payload)
        return packet

    def handle_created(self, packet):
        if packet.dest != self.id:
            return None
        dh_pub_key, key_hash = packet.msg
        encrypted_dh_pair = self.aes_encrypt("{}|||||{}".format(dh_pub_key, key_hash), self.__dh_sharedkey)
        self.send_packet(self.hop_table[1].prev, OP.EXTENDED, (encrypted_dh_pair, None))

    # Encrypts the msg
    def aes_encrypt(self, msg, key):
        padding_len = len(msg) % 16
        msg += " " * padding_len
        obj = AES.new(key[0:32], AES.MODE_CBC, 'This is an IV456')
        enc_msg = obj.encrypt(msg)
        return enc_msg
