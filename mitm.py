import os,binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aesLongKeyGen16 import *

#Subroutine for encryption
def aesEncrypt(message_bytes,cipher):
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
    return ciphertext
#Subroutine for decryption
def aesDecrypt(message_bytes,cipher):
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(message_bytes) + decryptor.finalize()
    return plaintext



ciphertexts = [
"ea7f6a9b8ca5641e5c574000342a6322",
# "24194bf1995f73a675ddabddbde46c43",
# "b7f2292330b32d43f351a9588bdfa640",
# "85c9b1e834c4c361db037023520fb438",
# "c85afb6a2947ee3497ddf2b10e3ac81b"
]

plaintexts=[
"Hydrodynamometer",
# "Circumnavigation",
# "Crystallographer",
# "Microphotography"
]


iv=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
allKey = {}
allKeyList = []

def decryptCipher(shortKeyBytes,ciphertext):
    # shortKeyBytes = value_bytes
    shortKey=bytearray(shortKeyBytes)
    longKey=expandKey(shortKey)
    cipher = Cipher(algorithms.AES(longKey), modes.CBC(iv))
    btwncipher=aesDecrypt(ciphertext,cipher)
    return btwncipher

for i in range(2**16):
    value_bytes = i.to_bytes(2, byteorder='big')
    # print(f"For {i} {value_bytes}")
    shortKeyBytes = value_bytes
    binary_representation = binascii.hexlify(shortKeyBytes).decode('utf-8')
    shortKey1=bytearray(shortKeyBytes)
    longKey1=expandKey(shortKey1)
    cipher1 = Cipher(algorithms.AES(longKey1), modes.CBC(iv))
    message_bytes=plaintexts[0].encode('UTF-8')
    # Encrypting message and Generating Cipher 
    ciphertext = aesEncrypt(message_bytes,cipher1)        
    # adding the  hex cipher to allKey dictionary
    allKey[ciphertext.hex()] = {"key":shortKeyBytes}

    # adding the hex cipher to allKeyList List
    allKeyList.append(ciphertext.hex())
    # print(allKey)

for i in range(2**16):
    value_bytes = i.to_bytes(2, byteorder='big')
    ciphertext=bytes.fromhex(ciphertexts[0])

    #Decrytpting ciphertext and Generating Cipher 
    btwncipher = decryptCipher(value_bytes,ciphertext)

    hex_cipher = btwncipher.hex()
    #check if ciphertext is already in allKeyList
    if(hex_cipher in allKeyList):
        print(f"First key => ",allKey[hex_cipher].get("key"))
        print(f"second key => {value_bytes}")
        fifthCipherText = bytes.fromhex("c85afb6a2947ee3497ddf2b10e3ac81b")
        resultCipher  = decryptCipher(value_bytes,fifthCipherText)


        secondShortKeyBytes = allKey[hex_cipher].get('key')
        plainText = decryptCipher(secondShortKeyBytes,resultCipher)
        print("plain text",plainText)
        break
