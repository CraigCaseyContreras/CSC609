import random
import string
import sys
import os
import argparse
from Bozhu_AES import AES, pad, __init__

#
# encrypt.py
#
# author:
# date:
# last update:
#
# template by: bjr sep 2019
# template update: 24 sep 2019
#

args_g = 0  # args are global

BLOCK_SIZE = 16  # the AES block size
KEY_SIZE = 16    # the AES key size


aes = AES(bytes(KEY_SIZE))
#bintext = "Hello World!!"


#HERE IS THE IV
IV= b'\01' * 16
string = "hello world"
#HERE IS THE MESSAGE
Plaintext = string.encode('utf-8')
print("Bit string: ", Plaintext, "Length: ", len(Plaintext))
print("The IV is: ", IV)
print("The length of the IV is: ", len(IV))
ciphertext = aes.encrypt_cbc(Plaintext,IV)
print(ciphertext)
xored = bytes(i^j for i, j in zip(Plaintext, IV))
print(xored, "XORED")
