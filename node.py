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
from threading import *

"""
Sequence for Arguments when running:
clientIP clientPort selfPort nextNodeIp nextNodePort privateKey
Python3 node.py 127.0.0.1 1234 1235 127.0.0.1 1236 123
"""

CLIENT = (sys.argv[1], int(sys.argv[2]))
SELF_NODE = ("127.0.0.1", int(sys.argv[3]))
NODE_AFTER = (sys.argv[4], int(sys.argv[5]))
NODE_PRIV_KEY = int(sys.argv[6])

print("Client info: " + str(CLIENT))
print("Self info: " + str(SELF_NODE))
print("Post-Node info: " + str(NODE_AFTER))

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


"""
#initial DH handshake, node recieves the p, g and mixed value from client
def DH_recieve_keys():
    print("Waiting to recieve DH Key")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    #prevents the program from double binding to the same port
    try:
        s.bind(SELF_NODE)
    except OSError:
        print()
    
    message_in = s.recvfrom(1024)
    message = message_in[0]
    returnDict = pickle.loads(message)
    
    #Makes sure that it got the right dictionary
    if "encoded" in returnDict:
        print("Initial DH Recieved")
        return returnDict
    else:
        print("Msg interpreted as DH")
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSocket.sendto(pickle.dumps(returnDict), SELF_NODE)
        DH_recieve_keys()
    
#return DH handshake, node returns its unique key
def DH_return_key_info(mainDict, CLIENT_INFO):
    print("Attempting to send DH key")
    mainDict["encoded"] = diffe_Hellman_step(mainDict["p"], mainDict["g"], NODE_PRIV_KEY)
    mainDictStr = pickle.dumps(mainDict)
    
    #sends the data over
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.sendto(mainDictStr, CLIENT_INFO)
    print("DH Key sent")
    return 0
    
#uses the client's DH key to determine the overall final key
def DH_final_key_gen(mainDict):
    return diffe_Hellman_step(mainDict["p"], mainDict["encoded"], NODE_PRIV_KEY)

#listens for the actual message being sent
def recieve_message():
    print("Listening for incoming msg")
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    #prevents the program from double binding to the same port
    try:
        s.bind(SELF_NODE)
    except OSError:
        print()
        
    message_in = s.recvfrom(1024)
    message = message_in[0]
    returnDict = pickle.loads(message)
    
    #Makes sure that it got the right dictionary
    if "Message" in returnDict:
        print("Msg received")
        return returnDict
    else:
        print("DH interpreted as Msg")
        recieve_message()
    
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
    
class ClientSet(Thread):
    def run(self):
        t1 = Thread(target = self.recieve_msg())
        t1.start()
        self.recieve_msg()

    def insert(self, newClient):
        clientDict[newClient.identifier] = newClient
    
    
    def __init__(self):
        global clientDict
        clientDict = { }
        Thread.__init__(self)
        
    def recieve_msg(self):
        print("Listening for incoming msg -- clientSet")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(SELF_NODE)
        message_in = s.recvfrom(1024)
        print("Data recieved")
        s.close()
    
        #got a new message, spawn another thread to continue watching for incoming
        
        print("Continuing")
        message = message_in[0]
        returnDict = pickle.loads(message)
        print(returnDict)
        
        #person already exists within clientList
        name = returnDict["identifier"]
        if name in clientDict:
            print(clientDict)
            clientDict[name].processMessage(returnDict, clientDict)
            #after forwarding the message
            del clientDict[name]
            
        else:
            print("New client initialized")
            CLIENT1 = Client(name)
            self.insert(CLIENT1)
            clientDict[name].processDH(returnDict)


class Client():
    def __init__(self, identifier):
        self.NODE_AFTER = NODE_AFTER
        self.identifier = identifier
        
    def processMessage(self, message_in):
        #nonce is sorted in reverse order based on the encryption
        nonce = message_in["Nonces"].pop()
        MD5_key = hashlib.md5(str(DH_encryption_key).encode()).hexdigest()

        #peel off one layer from "the onion"
        message_in["Message"] = decrypt_message(MD5_key, message_in["Message"], nonce)
        
        try:
            print(message_in["Message"].decode("utf8"))
        except UnicodeDecodeError:
            print("Not fully decoded")
            communicate_post(message_in, NODE_AFTER)
        return
    
    def processDH(self, DH_in):
        
        #determines the final key locally
        DH_encryption_key = DH_final_key_gen(DH_in)
        #print("Diffe-Hellman Key: " + str(DH_encryption_key))

        #determines the private key to send back
        DH_return_key_info(DH_in, CLIENT)
            
    global DH_encryption_key
    
c1 = ClientSet()
c1.run()
