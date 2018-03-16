from Client import Client
from Node import Node

if __name__ == "__main__":
    #  Create the nodes that will be used in creating a circuit
    client = Client()
    #  In TOR, these nodes would be selected randomly from the Directory of nodes
    node1 = Node()
    node2 = Node()
    node3 = Node()

    # send a CREATE message from Client to Node 1
    client.sendCreate()

    # TODO make a listener for messages in Node and in Client?

