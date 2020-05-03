"""
Role of the node is to recieve messages from either client, server or another
node and relay the message
"""
from Diffe_Hellman import *
import hashlib
import pickle

#not real ip addresses for now
NODE_AFTER = ("192.0.0.1", 0)
CLIENT = ("192.0.0.1", 0)
NODE_PRIV_KEY = 356094
p_val = 355933
g_val = 355633

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
    mainDict = {}
    ## TO DO ##
    #Replace with code expecting incoming dict with following values:
    #also: p_val, g_val
    print("Waiting to recieve DH Key")
    mainDict["encoded"] = 232862
    return mainDict
    
def DH_return_key_info(mainDict, CLIENT_INFO):
    #replace with code to send the mainDict to the node that sent it
    print("Waiting to send DH key")
    mainDict["encoded"] = diffe_Hellman_step(p_val, g_val, NODE_PRIV_KEY)
    mainDictStr = pickle.dumps(mainDict)
    
    #sends the data over
    # clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # clientSocket.sendto(mainDictStr, CLIENT_INFO)

    return ""
    
def DH_final_key_gen(mainDict):
    return diffe_Hellman_step(p_val, mainDict["encoded"], NODE_PRIV_KEY)

#Function should listen for incoming messages
def recieve_message():
    ## TO DO ##
    print("Listening for incoming msg")
    ## TO DO ##
    returnDict = {"Message": 10}
    return returnDict

#decrypt the message that comes in
def decrypt_message(encryption_key, msg, nonce):
    decryptionCipher = AES.new(key.encode("utf8"), AES.MODE_EAX, nonce)
    message = decryptionCipher.decrypt(message)
    return message

#Sends the info to the next node
def communicate_post(msgDict, reciever_info):
    #send the msgDict to reciever_info
    print("Sending msg to next node")
    msgDictStr = pickle.dumps(msgDict)
    
    # clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # clientSocket.sendto(mainDictStr, reciever_info)
    return 0
    

DH_msg_dict = DH_recieve_keys();
#determines the final key locally
DH_encryption_key = DH_final_key_gen(DH_msg_dict)

#determines the private key to send back
DH_return_key_info(DH_msg_dict, CLIENT)



message_in = recieve_message()
nonce = message_in["Nonces"].pop()
MD5_key = hashlib.md5(str(key).encode()).hexdigest()

message_in["Message"] = decrypt_message(MD5_key, message_in["Message"], nonce)

communicate_post(message_in, NODE_AFTER)
