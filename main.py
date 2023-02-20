import json
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import time
import argparse
from random import randint
from utils_demo import *

#print function
def PrintStr(ctype, val):
    print(ctype, ': ', val)

#function to increment key to be searched
def UpdateKey(val):

    new_key = int.from_bytes(val, 'big')
    new_key += 1
    new_key = bitstring_to_bytes(bin(new_key))

    return new_key

#driver function
def main():
    
    #read plaintext from files
    m1 = string_to_bytes(read_file('m1.txt'))
    m2 = string_to_bytes(read_file('m2.txt'))
    m3 = string_to_bytes(read_file('m3.txt'))

    PrintStr('m1', m1)
    PrintStr('m2', m2)
    PrintStr('m3', m3)

    #read ciphertext from files
    c1 = read_bytes('c1.bin')
    c2 = read_bytes('c2.bin')
    c3 = read_bytes('c3.bin')

    PrintStr('c1', c1)
    PrintStr('c2', c2)
    PrintStr('c3', c3)

    #read nonce from files
    nonce1 = read_bytes('nonce1.bin')
    nonce2 = read_bytes('nonce2.bin')
    nonce3 = read_bytes('nonce3.bin')

    PrintStr('nonce1', nonce1)
    PrintStr('nonce2', nonce2)
    PrintStr('nonce3', nonce3)

    #create max value for 128 bit key
    full_key_val = 2**127

    #create key value for 24 bit key
    partial_key_val = 2**24

    #create byte string  for 128 bit key
    full_key = bitstring_to_bytes(bin(full_key_val))
    PrintStr('128-bit key', full_key)

    #loop to check all key possibilites for matching key
    for i in range(partial_key_val):

        try:
            pt1 = decryptor_CTR(c1, nonce1, full_key)

            if(pt1.decode() == m1.decode()):
                print('matching key: ', full_key)
                print('decrypted plaintext: ', pt1)

        except:
            pass

        UpdateKey(full_key)

    print('finished search')

if __name__=="__main__":
    main()

