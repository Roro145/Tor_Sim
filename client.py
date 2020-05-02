from Diffe_Hellman import *
from Crypto.Cipher import AES
import hashlib


NodeList = ["128.0.0.1", "196.0.0.1", "124.0.0.1"]
DHKeyList = []
MD5KeyList = []
DH_vals = {"p": 11, "g": 13}
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
    print("Sending DH_mixed key")
    DH_dict["encoded"] = DH_mixed
    send_initial_DH(DH_dict, NodeIP)
    
    otherDict = recieve_DH()
    assert(otherDict["p"] == DH_dict["p"] and otherDict["g"] == DH_dict["g"])
    final_dh_key = diffe_Hellman_step(otherDict["p"], otherDict["g"], otherDict["encoded"])
    
    return final_dh_key
    
def send_initial_DH(dict1, node):
    print("Sending " + str(dict1) + " to node: " + node)
    return 0


def recieve_DH():
    print("Recieving DH_mixed key")
    #recieved dict:
    returnDict = {"p": 11, "g": 13, "encoded": 9}

    return returnDict

for ip in NodeList:
    current_DH_key = DH_key_exchange(DH_vals, CLIENT_PRIV_KEY, ip)
    DHKeyList.append(current_DH_key)
    
DHKeyList = [11, 15, 17]
for key in DHKeyList:
    MD5KeyList.append(hashlib.md5(str(key).encode()).hexdigest())
    

print(DHKeyList)
print(MD5KeyList)

#This triple encodes the message
message = "abc".encode("utf8")
print(message)
nonceList = []
for key in MD5KeyList:
    cipher = AES.new(key.encode("utf8"), AES.MODE_EAX)
    message, tag = cipher.encrypt_and_digest(message)
    nonceList.append(cipher.nonce)
    print(message)
    
print("Decryption: ")
for x in range(len(MD5KeyList)-1, -1, -1):
    key = MD5KeyList[x]
    cipher = AES.new(key.encode("utf8"), AES.MODE_EAX)
    decryptionCipher = AES.new(key.encode("utf8"), AES.MODE_EAX, nonceList[x])
    message = decryptionCipher.decrypt(message)


print(message.decode("utf-8"))

"""
plaintext = decryptCipher.decrypt_and_verify(message, tag)
print(plaintext.decode("utf-8"))


"""
