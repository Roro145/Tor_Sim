"""
Role of the node is to recieve messages from either client, server or another
node and relay the message
"""
from Diffe_Hellman import *
import hashlib
from Crypto.Cipher import AES
import pickle
import socket
import sys

"""
Sequence for Arguments when running:
0 - listen port
1 - forward ip
2 - forward port
"""

#not real ip addresses for now
SELF_NODE = ("127.0.0.1", 1235)
NODE_AFTER = ("127.0.0.1", 1236)
CLIENT = ("127.0.0.1", 1234)
NODE_PRIV_KEY = 17

"""
Node steps:

DH:
1) recieve information from client - {p_val, g_val, encoded}
2) encode it using current priv key
3) send dictionary back - excluding the final key
- at this point the node and sender can create the master private key -

Processing:
1) recieve message
2) decode message using private key

Sending:
1) Send msg to the next node
"""

"""
Function descriptions
DH_recieve_keys - recieves the DH values from client, node or server
DH_return_key_info - creates the local DH key, sends it back
DH_final_key - Determines the Pre-SHA256 hash key

"""

def DH_recieve_keys():
    print("Waiting to recieve DH Key")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(SELF_NODE)
    message_in = s.recvfrom(1024)
    message = message_in[0]
    returnDict = pickle.loads(message)
    print("Initial DH Recieved")
    
    return returnDict
    
def DH_return_key_info(mainDict, CLIENT_INFO):
    print("Attempting to send DH key")
    mainDict["encoded"] = diffe_Hellman_step(mainDict["p"], mainDict["g"], NODE_PRIV_KEY)
    mainDictStr = pickle.dumps(mainDict)
    
    #sends the data over
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.sendto(mainDictStr, CLIENT_INFO)
    print("DH Key sent")
    return 0
    
def DH_final_key_gen(mainDict):
    return diffe_Hellman_step(mainDict["p"], mainDict["encoded"], NODE_PRIV_KEY)

#Function should listen for incoming messages
def recieve_message():
    print("Listening for incoming msg")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(SELF_NODE)
    message_in = s.recvfrom(1024)
    message = message_in[0]
    returnDict = pickle.loads(message)
    print("Msg received")
    return returnDict

#decrypt the message that comes in
def decrypt_message(encryption_key, msg, nonce):
    decryptionCipher = AES.new(encryption_key.encode("utf8"), AES.MODE_EAX, nonce)
    message = decryptionCipher.decrypt(msg)
    print("Decryption Successful")
    return message

#Sends the info to the next node
def communicate_post(msgDict, reciever_info):
    #send the msgDict to reciever_info
    print("Sending Message to Next Node")
    mainDictStr = pickle.dumps(msgDict)
    
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.sendto(mainDictStr, reciever_info)
    return 0
    

DH_msg_dict = DH_recieve_keys();

#determines the final key locally
DH_encryption_key = DH_final_key_gen(DH_msg_dict)
print("Diffe-Hellman Key: " + str(DH_encryption_key))

#determines the private key to send back
DH_return_key_info(DH_msg_dict, CLIENT)

message_in = recieve_message()
nonce = message_in["Nonces"].pop()
MD5_key = hashlib.md5(str(DH_encryption_key).encode()).hexdigest()

print(MD5_key)

message_in["Message"] = decrypt_message(MD5_key, message_in["Message"], nonce)
print(message_in["Message"].decode("utf8"))

communicate_post(message_in, NODE_AFTER)
