from  diffiehellman.diffiehellman import DiffieHellman
import rsa

class Client:
    DHKE = ""

    def __init__(self):
        self.DHKE = DiffieHellman()
        self.DHKE.generate_public_key()  # automatically generates private key

    def onReceiptOfCREATED(self, other_public_key):
        self.DHKE.generate_shared_secret(other_public_key, echo_return_key=True)

    def onReceiptOfEXTENDED(self):
        pass

    def sendCreate(self, message, rsaPubKeyOfReceiver):
        # encrypt message to RSA public key of receiver
        msg = 'This should be the create message'.encode('utf8')
        cipher = rsa.encrypt(message, rsaPubKeyOfReceiver)
        # send message to specified node
        pass

