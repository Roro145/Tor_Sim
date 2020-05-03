from Diffe_Hellman import *
from Crypto.Cipher import AES
import socket
import hashlib
import pickle
import time


NodeList = [("127.0.0.1", 1235), ("127.0.0.1", 1236), ("127.0.0.1", 1237)]
#NodeList = [("127.0.0.1", 1235), ("127.0.0.1", 1236)]
#NodeList = [("127.0.0.1", 1235)]
CLIENT_NODE = ("127.0.0.1", 1234)
DHKeyList = []
MD5KeyList = []
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

def DH_key_exchange(DH_dict, priv_key, NodeIP):
    DH_mixed = diffe_Hellman_step(DH_dict["p"], DH_dict["g"], priv_key)
    print("Sending DH_mixed key to " + str(NodeIP))
    DH_dict["encoded"] = DH_mixed
    
    send_initial_DH(DH_dict, NodeIP)
    
    otherDict = recieve_DH()
    assert(otherDict["p"] == DH_dict["p"] and otherDict["g"] == DH_dict["g"])
    final_dh_key = diffe_Hellman_step(otherDict["p"], otherDict["encoded"], priv_key)
    print("Diffe-Hellman Key: " + str(final_dh_key))
    
    return final_dh_key
    
def send_initial_DH(dict1, node):
    print("Sending " + str(dict1) + " to node: " + str(node))
    dictStr = pickle.dumps(dict1)
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.sendto(dictStr, node)
    
    return 0


def recieve_DH():
    print("Recieving DH_mixed key")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(CLIENT_NODE)
    message_in = s.recvfrom(1024)
    message = message_in[0]
    returnDict = pickle.loads(message)
    
    print("DH received")
    return returnDict
    
def send_msg(infoDict, node):
    print("Sending: " + str(infoDict) + " to " + str(node))
    dictStr = pickle.dumps(infoDict)
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.sendto(dictStr, node)
    print("Message sent")
    return 0

for ip in NodeList:
    current_DH_key = DH_key_exchange(DH_vals, CLIENT_PRIV_KEY, ip)
    DHKeyList.append(current_DH_key)
    
print(DHKeyList)
for key in DHKeyList:
    MD5KeyList.append(hashlib.md5(str(key).encode()).hexdigest())


#This triple encodes the message
message = "testing01".encode("utf8")
print(message)
nonceList = []
for x in range(len(MD5KeyList)-1, -1, -1):
    key = MD5KeyList[x]
    cipher = AES.new(key.encode("utf8"), AES.MODE_EAX)
    message, tag = cipher.encrypt_and_digest(message)
    nonceList.append(cipher.nonce)
    print(key)

time.sleep(2)
forwardMsg = {"Nonces": nonceList, "Message": message}
send_msg(forwardMsg, NodeList[0])

#Each node should use the nonce value at the end of the list
"""
#DECODING PROCESS:
for x in range(len(MD5KeyList)-1, -1, -1):
    key = MD5KeyList[x]
    cipher = AES.new(key.encode("utf8"), AES.MODE_EAX)
    print(cipher.nonce)
    decryptionCipher = AES.new(key.encode("utf8"), AES.MODE_EAX, nonceList[x])
    message = decryptionCipher.decrypt(message)

print(message.decode("utf-8"))
"""
