"""
Role of the node is to recieve messages from either client, server or another
node and relay the message
"""
from Diffe_Hellman import *
import hashlib

#not real ip addresses for now
NODE_AFTER = "192.0.0.1"
CLIENT = "192.0.0.1"
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
    #Replace with code expecting incoming dict with following values:
    #also: p_val, g_val
    print("Waiting to recieve DH Key")
    mainDict["encoded"] = 232862
    return mainDict
    
def DH_return_key_info(mainDict):
    #replace with code to send the mainDict to the node that sent it
    print("Waiting to send DH key")
    mainDict["encoded"] = diffe_Hellman_step(p_val, g_val, NODE_PRIV_KEY)
    
    return ""
    
def DH_final_key_gen(mainDict):
    return diffe_Hellman_step(p_val, mainDict["encoded"], NODE_PRIV_KEY)

#Function should listen for incoming messages
def recieve_message():
    print("Listening for incoming msg")
    returnDict = {"Message": 10}
    return returnDict

#decrypt the message that comes in
def decrypt_message(encryption_key, msg):
    print("Decryping message coming in")
    print("The message is: ")
    return " "

#Sends the current encoded, returns their encoded
def communicate_post(msgDict, reciever_info):
    #send the msgDict to reciever_info
    print("Sending msg to next node")
    return 0
    

DH_msg_dict = DH_recieve_keys();
DH_encryption_key = DH_final_key_gen(DH_msg_dict)

DH_return_key_info(DH_msg_dict)

SHA_KEY = hashlib.sha256(str(DH_encryption_key).encode()).hexdigest()
print(SHA_KEY)

message_in = recieve_message()

forwardDict = {}
forwardDict["Message"] = decrypt_message(SHA_KEY, message_in["Message"])
communicate_post(forwardDict, NODE_AFTER)
