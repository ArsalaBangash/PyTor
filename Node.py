from diffiehellman.diffiehellman import DiffieHellman
import rsa


class Node:
    DHKE = None
    (pubkey, privkey) = None  #  RSA keys

    def __init__(self):
        self.DHKE = DiffieHellman()
        self.DHKE.generate_public_key()  # automatically generates private key
        (self.pubkey, self.privkey) = rsa.newkeys(512)

    def onReceiptOfCREATE(self, cipher, clientDHKE_halfkey):
        msg = rsa.decrypt(cipher, self.privkey)

        # TODO send our part of the DHKE to the sender!
        # self.DHKE.getPublicKey()?
        self.DHKE.generate_shared_secret(clientDHKE_halfkey, echo_return_key=True)

    def onReceiptOfCREATED(self, other_public_key):
        pass

    def onReceiptOfEXTENDED(self):
        pass

    def sendMessage(self, message):
        pass

    def processIncomingMessage(self):
        pass
