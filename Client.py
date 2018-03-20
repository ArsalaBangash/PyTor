from  diffiehellman.diffiehellman import DiffieHellman
from pydispatch import dispatcher
import rsa

class Client:
    DHKE = ""

    def __init__(self):
        self.DHKE = DiffieHellman()
        self.DHKE.generate_public_key()  # automatically generates private key

        # https://github.com/isislovecruft/leekspin
        # We can add this to the nodes and Client, it's p. cool!

    def handleIncomingMsg(sender, msg):
        """Simple event handler"""
        print ('Signal was sent by', sender)
        dispatcher.connect(handleIncomingMsg, signal=msg, sender=dispatcher.Any)
        # Do stuff with msg now. Call the related function? OR do stuff right here in a SWITCH?

    def sendMessage(self, receiver):
        # encrypt message to RSA public key of receiver
        msg = 'This should be the create message'.encode('utf8')
        cipher = rsa.encrypt(msg, receiver.pubkey)

        # send message to specified node
        dispatcher.send(signal=cipher, sender=self)

    def onReceiptOfCREATED(self, other_public_key):
        self.DHKE.generate_shared_secret(other_public_key, echo_return_key=True)

    def onReceiptOfEXTENDED(self):
        pass



