from Diffe_Hellman import *
from Crypto.Cipher import AES
import socket
import hashlib
import pickle
import time
import sys

NodeList = [("127.0.0.1", 1235), ("127.0.0.1", 1236), ("127.0.0.1", 1237)]
NodeList = [("127.0.0.1", 1235)]
CLIENT_NODE = ("127.0.0.1", 1234)
DH_vals = {"p": 1113, "g": 1333}
CLIENT_PRIV_KEY = 15

"""
DH-Key Exchange
1 - send DH key values to each node
2 - recieve their private DH values
3 - determine the final DH final, for each node

Encryption
1 - encrypt message using k3, k2, k1

Forward
1 - send message to node 1
"""

def DH_key_exchange(DH_dict, priv_key, NodeIP, identity):
    DH_mixed = diffe_Hellman_step(DH_dict["p"], DH_dict["g"], priv_key)
    print("Sending DH_mixed key to " + str(NodeIP))
    DH_dict["encoded"] = DH_mixed
    DH_dict["identifier"] = identity
    send_info(DH_dict, NodeIP)
    
    otherDict = recieve_DH()
    assert(otherDict["p"] == DH_dict["p"] and otherDict["g"] == DH_dict["g"])
    final_dh_key = diffe_Hellman_step(otherDict["p"], otherDict["encoded"], priv_key)
    print("Diffe-Hellman Key: " + str(final_dh_key))
    
    return final_dh_key
    


def send_info(infoDict, node):
    print("Sending: " + str(infoDict) + " to " + str(node))
    dictStr = pickle.dumps(infoDict)
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.sendto(dictStr, node)
    print("Message sent")


def recieve_DH():
    print("Recieving DH_mixed key")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(CLIENT_NODE)
    message_in = s.recvfrom(1024)
    message = message_in[0]
    returnDict = pickle.loads(message)
    
    print("DH received")
    return returnDict
    


def initiate_DH_handshake_master(NodeList, identity):
    DHKeyList = []
    MD5KeyList = []
    for ip in NodeList:
        current_DH_key = DH_key_exchange(DH_vals, CLIENT_PRIV_KEY, ip, identity)
        DHKeyList.append(current_DH_key)
        
    print(DHKeyList)
    for key in DHKeyList:
        MD5KeyList.append(hashlib.md5(str(key).encode()).hexdigest())
    
    return MD5KeyList

def encrypt_and_send_master(identity, message_in, MD5KeyList, Node1):
    #encodes the message
    message = str(message_in).encode("utf8")
    nonceList = []
    for x in range(len(MD5KeyList)-1, -1, -1):
        key = MD5KeyList[x]
        cipher = AES.new(key.encode("utf8"), AES.MODE_EAX)
        message, tag = cipher.encrypt_and_digest(message)
        nonceList.append(cipher.nonce)

    time.sleep(2)
    forwardMsg = {"identifier": identity, "Nonces": nonceList, "Message": message}
    send_info(forwardMsg, Node1)
    return 0


try:
    message_in = sys.argv[2]
    IDENTIFIER = sys.argv[1]
except:
    message_in = "None Found"
    IDENTIFIER = "N/A"

MD5KeyList = initiate_DH_handshake_master(NodeList, IDENTIFIER)

encrypt_and_send_master(IDENTIFIER, message_in, MD5KeyList, NodeList[0])
