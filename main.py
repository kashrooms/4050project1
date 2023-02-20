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

#function to increment key to be searched by 1
def UpdateKey(val):

    #convert key from bytes to integer
    new_key = int.from_bytes(val, 'big')

    #increment by 1
    new_key += 1

    #convert key back to bytes
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
    c_c = read_bytes('c_c.bin')

    PrintStr('c1', c1)
    PrintStr('c2', c2)
    PrintStr('c3', c3)

    #read nonce from files
    nonce1 = read_bytes('nonce1.bin')
    nonce2 = read_bytes('nonce2.bin')
    nonce3 = read_bytes('nonce3.bin')
    nonce_c = read_bytes('nonce_c.bin')

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

    curr_key = full_key

    #loop to check all key possibilites for matching key
    for i in range(partial_key_val):

        try:

            #decrypt using given ciphertext1, nonce1, and current key possibility
            pt1 = decryptor_CTR(c1, nonce1, curr_key)

            #check if decrypted plaintext matches given plaintext1
            if(pt1.decode() == m1.decode()):

                #decrypt remaining plaintext/ciphertext pairs
                pt2 = decryptor_CTR(c2, nonce2, curr_key)
                pt3 = decryptor_CTR(c3, nonce3, curr_key)

                #check if decrypted plaintext matches given m2 and m3
                if(pt2.decode() == m2.decode() and pt3.decode() == m3.decode()):

                    #get challenge message using found key and given nonce and ciphertext
                    pt_c = decryptor_CTR(c_c, nonce_c, curr_key)

                    #convert found key to bit string
                    found_key = bin(int.from_bytes(curr_key, 'big'))
            
                    #print decrypted plaintext and matching key
                    print('decrypted plaintext 1: ', pt1.decode())
                    print('decrypted plaintext 2: ', pt2.decode())
                    print('decrypted plaintext 3: ', pt3.decode())
                    print('challenge plaintext: ', pt_c.decode())
                    print('matching key in hex bytes: ', curr_key)
                    print('matching key in bits: ', found_key)

                    #write message and key to file
                    write_file('keystr.txt', found_key)
                    write_file('m_c.txt', pt_c.decode())

                    break

        except:
            pass

        #increment current key by 1
        curr_key = UpdateKey(curr_key)

    print('Done...')

if __name__=="__main__":
    main()

