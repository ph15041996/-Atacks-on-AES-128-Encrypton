import os,json

import os,binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aesLongKeyGen24 import *
def GetKeyFromCipher(shortKeyBytes):
    shortKey=bytearray(shortKeyBytes)
    # print(f"Short key {shortKey.hex()} type {type(shortKeyBytes)} ",shortKeyBytes)
    #Expand key to 128 bits
    key=expandKey(shortKey)
    # print("Expanded short key",key,type(key))

    #Set up iv and cipher
    iv=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    #Read and encrypt messages

    ciphertexts=[
    'fe0f42ae809fe1e2ff5b59725ef52048',
    # 'ab4e40c6bf551a4d0794c0fd65074003',
    # 'ffc7bb77f95466128a61f4ad9916b8ca',
    # 'd9ff735a89509dc5c23d2eb27cf00904',
    # 'ca6889853e3ddfaf621b87ee4966e27'
    ] 

    messages=[
    'Counterclockwise',
    # 'sonicthehedgehog',
    # 'TheDeterminantor',
    # 'FeedbackRegister'
    ]
    lenMsg = len(messages) 
    for ind in range(lenMsg):
        message=messages[ind]
        message_bytes=message.encode('UTF-8')
        # print(f"Msg bytes {message_bytes}")
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message_bytes) + encryptor.finalize()        
        if(ciphertext.hex() == ciphertexts[0]):
            # print("ok",shortKeyBytes)
            print("Cipher text {} message {} shortKeyBytes {} cipher hex".format(ciphertext,message,shortKeyBytes),ciphertext.hex())
            print("Short Key Bytes",shortKeyBytes)
            return shortKeyBytes


        return None

def GetMsgFormCipher(shortKeyBytes):

    shortKey=bytearray(shortKeyBytes)
    iv=b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'
    key=expandKey(shortKey)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    secretcipher = bytes.fromhex("ca6889853e3ddfaf621b87ee4966e274")
    plain=decryptor.update(secretcipher)+decryptor.finalize()
    print("Secret=",secretcipher.hex()," plain= ",plain,"plain_hex= ",plain.hex())
    print("Plain Text => ",plain)

for i in range(2**24):
    shortKeyBytes = (i<<4).to_bytes(3, byteorder='big')
    decKey =  GetKeyFromCipher(shortKeyBytes)
    if(decKey):
        GetMsgFormCipher(decKey)
        break
        
