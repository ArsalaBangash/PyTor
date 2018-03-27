from pydispatch import dispatcher
from utils import OP
from packet import Packet
import rsa
import hashlib
from diffiehellman.diffiehellman import DiffieHellman


class Client:
    DHKE = ""

    def __init__(self):
        self.dhke = DiffieHellman()
        print(self.dhke.key_length)
        # automatically generates private key
        self.dhke.generate_public_key()
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        self.__dh_sharedkey = None

        print(self.dhke.public_key)
        self.send_ops = {
            OP.CREATE: self.get_create_message
        }
        # Set once we establish a connect to an entry node
        self.entry_node = None
        # the client is listening to any CREATED messages
        dispatcher.connect(self.handle_created, signal=OP.CREATED,
                           sender=dispatcher.Any)
        dispatcher.connect(self.handle_extended, signal=OP.EXTENDED,
                           sender=dispatcher.Any)

    def get_create_message(self, receiver):
        msg = self.dh_pub
        enc_msg = rsa.encrypt(msg, receiver.pubkey)
        packet = Packet(src_id="client", op=OP.CREATE,
                        dest=receiver.id, payload=(enc_msg, None))
        return packet

    def send_message(self, receiver, op):
        packet = self.send_ops[op](receiver)
        dispatcher.send(signal=op, sender=self, packet=packet)

    def handle_created(self, packet):
        (other_key, keyHash) = packet.msg
        # Generate the shared key
        shared = self.dhke.generate_shared_secret(other_key)
        mykeyHash = hashlib.sha1(
            str(self.__dh_sharedkey).encode("utf-8")).hexdigest()

        if mykeyHash == keyHash:  # Only go through if hash mataches
            self.__dh_sharedkey = shared
            self.entry_node = packet.src
            print("Client's entry node is now set to: ", self.entry_node)

    def handle_extended(self, packet):
        # TODO:
        (other_key, keyHash) = packet.msg

        pass

