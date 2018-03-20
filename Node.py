from diffiehellman.diffiehellman import DiffieHellman
from pydispatch import dispatcher
import rsa


class Node:
    DHKE = None
    (pubkey, privkey) = (None, None)  #  RSA keys

    def __init__(self):
        self.DHKE = DiffieHellman()
        self.DHKE.generate_public_key()  # automatically generates private key
        (self.pubkey, self.privkey) = rsa.newkeys(512)

    def sendMessage(self, receiver):
        msg = 'My message to the receiver'.encode('utf8')

        # send message to specified node
        # TODO this actually broadcasts the message. How to specifically send to one node?
        dispatcher.sendExact(signal=msg, sender=self)

    def handleIncomingMsg(self, sender, msg, op):
        """Simple event handler"""
        print ('Signal was sent by', sender)
        dispatcher.connect(self.handleIncomingMsg, signal=msg, sender=dispatcher.Any)

        # Pass the message on to the right handler
        switch ={
            op.CREATE: self.handleCREATE,
            op.CREATED: self.handleCREATED
        }
        switch[op]

    def handleCREATE(self, cipher, clientDHKE_halfkey):
        msg = rsa.decrypt(cipher, self.privkey)
        if msg is None: # TODO check if message is garbage ie not for us.
            pass
        # TODO send our part of the DHKE to the sender!
        # self.DHKE.getPublicKey()?
        self.DHKE.generate_shared_secret(clientDHKE_halfkey, echo_return_key=True)

    def handleCREATED(self, other_public_key):
        pass

    def handleEXTEND(self):
        pass
    def handleEXTENDED(self):
        pass