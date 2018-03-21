from diffiehellman.diffiehellman import DiffieHellman
from pydispatch import dispatcher
from utils import OP
from utils import Packet
import rsa


class Client:
    DHKE = ""

    def __init__(self):
        self.DHKE = DiffieHellman()
        # automatically generates private key
        self.dh_pub = self.DHKE.generate_public_key()
        # https://github.com/isislovecruft/leekspin
        # We can add this to the nodes and Client, it's p. cool!

        send_ops = {
            op.CREATE: self.get_create_message
        }
        dispatcher.connect(handle_create, signal=op.CREATE,
                           sener=dispatcher.Any)

    def get_create_message(self, receiver):
        msg = self.dh_pub
        enc_msg = "DH_KEY{}".format(rsa.encrypt(msg, receiver.pubkey)_
        packet = Packet(op=OP.CREATE, dest=receiver.id, payload=enc_msg)
        return packet

    def receive_message(sender, msg):
        """Simple event handler"""
        print('Signal was sent by', sender)
        dispatcher.connect(handleIncomingMsg, signal=msg,
                           sender=dispatcher.Any)
        # Do stuff with msg now. Call the related function? OR do stuff right here in a SWITCH?

    def send_message(self, receiver, op):
        packet = self.send_ops[op](receiver)
        dispatcher.send(signal=op, sender=self, packet)

    def onReceiptOfCREATED(self, other_public_key):
        self.DHKE.generate_shared_secret(
            other_public_key, echo_return_key=True)

    def onReceiptOfEXTENDED(self):
        pass

    def handle_create(sender, packet):
        pass
