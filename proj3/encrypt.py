import random
import string
import sys
import os
import argparse
from Bozhu_AES import AES

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

#Whatever our plaintext is, needs to be padded with PKCS#7
#We don't have encrypt_cbc but we have encrypt_block(self, plaintext)
#We also have padding which is pad(plaintext)
#

#His bintext is b'hello world\n'
#His bintext AFTER crypt_ecb is b'\\GA\x8d{.\xf0\x92\x01\x93d<\xe0\xedN\x91'
#BOTH LENGTH 16

def crypt_cbc(aes, intext): #our intext right now is "hello world" so really all we have is "hello world" as the paramter

	#MUST ENCODE OR WONT LET YOU PAD!!!
	print(intext, "This is the intext of length: ", len(intext))
	message = intext.encode('utf-8')
	print(message, "This is the intext encoded of length: ", len(message))
	#pad the message
	paddedmessage = aes.pad(message)
	print(paddedmessage, "This is the padded message of length: ", len(paddedmessage))

	#Get the IV
	IV = b'\01' * 16
	print(IV, "This is the IV of length: ", len(IV))
	#Now we can encrypt and do the xor? Or do the xor first?
	#The code does the encrypt WITH the xor at the same time

	blokes = []
	prev = IV

	#Now we have to split into 16-byte parts
	for l in range(0, len(paddedmessage), 16):
		paddedBlock = paddedmessage[l:l+16]
		#CBC mode so XOR the block with before
		bloke = aes.encrypt_block(aes.xor_bytes(paddedBlock, prev))
		blokes.append(bloke)
		before = bloke
		print(b''.join(blokes), "Result from the for-loop")
	return b''.join(blokes)

	#----------------------------------------------------------------


def main():
	aes = AES(bytes(KEY_SIZE))
	message = "hello world"#.encode('utf-8') I used message instead of bintext
	crypt_cbc(aes, message);

if __name__== '__main__':
	main()
