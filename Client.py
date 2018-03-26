from pydispatch import dispatcher
from utils import OP
from packet import Packet
import rsa
from diffiehellman.diffiehellman import DiffieHellman


class Client:
    DHKE = ""

    def __init__(self):
        self.dhke = DiffieHellman()
        print(self.dhke.key_length)
        # automatically generates private key
        self.dhke.generate_public_key()
        self.dh_pub = str(self.dhke.public_key).encode('utf8')
        print(self.dhke.public_key)
        self.send_ops = {
            OP.CREATE: self.get_create_message
        }
        dispatcher.connect(self.handle_create, signal=OP.CREATE,
                           sender=dispatcher.Any)

    def get_create_message(self, receiver):
        msg = self.dh_pub
        enc_msg = rsa.encrypt(msg, receiver.pubkey)
        packet = Packet(src_id="client", op=OP.CREATE, dest=receiver.id, payload=(enc_msg, None))
        return packet

    def send_message(self, receiver, op):
        packet = self.send_ops[op](receiver)
        dispatcher.send(signal=op, sender=self, packet=packet)

    def handle_create(sender, packet):
        pass
