from Client import Client
from Node import Node
import time
if __name__ == "__main__":
    #  Create the nodes that will be used in creating a circuit
    client = Client()
    #  In TOR, these nodes would be selected randomly from the Directory of nodes
    node1 = Node()
    node2 = Node()
    node3 = Node()
    print("Created nodes to build the circuit (node1, node2, and node3).")

    print("Building the circuit:")


    # send a CREATE message from Client to Node 1. Node 1 decrypts it, and
    # sends Client back a CREATED message with its half of the DHKE. Client
    # creates the key and saves it.
    client.send_CREATE(node1, msg=cl)

    # Extend the circuit to node 2. Node1 sends a create message to node2
    # with the encrypted first half of DHKE. node2 replies with a CREATED
    # to node1, and then node1 replies to client with an EXTENDED.
    time.sleep(5)
    client.send_EXTEND(node1, msg=client.DHKE2.public_key, create=node2)

    # TODO try to view DHKE2 from node1 (should fail cuz no private key)
    time.sleep(5)
    client.send_EXTEND(node2, msg=client.DHKE3.public_key, create=node3)

    # Circuit complete. Now it's time to relay messages through.
    client.relay("Wooo - no one knows who sent this msg!")
    # TODO try to determine who client is from node3 (should fail as only node1
    # knows who the client is)
