from pydispatch import dispatcher
from utils import OP
from packet import Packet
import rsa
import os
import hashlib
from diffiehellman.diffiehellman import DiffieHellman
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Client:
    DHKE = ""
    def __init__(self):
        self.AESKeys = [] #stores all the DH shared keys in order
        self.dhke = DiffieHellman()
        print(self.dhke.key_length)
        # automatically generates private key
        self.dhke.generate_public_key()
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        self.__dh_sharedkey = None

        print(self.dhke.public_key)
        self.send_ops = {
            OP.CREATE: self.get_create_message,
            OP.EXTEND: self.get_extend_message
        }
        # Set once we establish a connect to an entry node
        self.entry_node = None
        # the client is listening to any CREATED messages
        dispatcher.connect(self.handle_created, signal=OP.CREATED,
                           sender=dispatcher.Any)

        ###Same bug as handle_created for handle_extended.... See handle_created
        dispatcher.connect(self.handle_extended, signal= OP.EXTEND,
                          sender=dispatcher.Any)

    def get_create_message(self, receiver):
        msg = self.dh_pub
        enc_msg = rsa.encrypt(msg, receiver.pubkey)
        packet = Packet(src_id="client", op=OP.CREATE, dest=receiver.id, payload=(enc_msg, None))
        return packet

    def send_message(self, receiver, op):
        packet = self.send_ops[op](receiver)
        dispatcher.send(signal=op, sender=self, packet=packet)

    ## TODO BUG: Current dispatcher system, announces the packet to all listeners. This allows for returning packets, messages, operations like
    ## created to skip the process of going back through the circuit and going directly to the client.
    def handle_created(self, packet):
        (other_key, keyHash) = packet.msg
        # Generate the shared key
        shared = self.dhke.generate_shared_secret(other_key)
        mykeyHash =  hashlib.sha1(str(self.__dh_sharedkey).encode("utf-8")).hexdigest()

        if mykeyHash == keyHash:  # Only go through if hash mataches
            self.__dh_sharedkey = shared
            print("we got here")
            print(shared)
            self.AESKeys.append(shared)
            self.entry_node = packet.src
            print("Client's entry node is now set to: ", self.entry_node)

    #Extend always gets wrapped with everything in the the AES Keys list
    def get_extend_message(self, receiver):
        msg = "Extend"
        msg = msg.encode('utf8')
        for i in reversed(self.AESKeys):
            print(i)
            msg = self.aes_encrypt(msg, receiver, i)
        packet = Packet(src_id="client", op=OP.EXTEND, dest=receiver.id, payload=(msg, self.get_create_message))
        return packet


    #Encrypts the msg
    def aes_encrypt(self, msg, receiver, key):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        enc_msg = encryptor.update(bytes(msg, encoding='utf-8')) + encryptor.finalize()
        return enc_msg

    def handle_extended(self, packet):
        pass
