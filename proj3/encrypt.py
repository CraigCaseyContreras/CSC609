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

def crypt_cbc(aes, intext, mode):
	#our intext right now is "hello world" so really all we have is "hello world" as the paramter
	#intext can also be a ciphertext so can be either one
	#if args.v.encrypt, intext is a plaintext,
	#if args.v.decrypt, intext is a ciphertext
	# Get the IV
	IV = b'\01' * 16
	#print(IV, "This is the IV of length: ", len(IV))

	if mode == "decrypt":
		cipherOf0padding = b'\x0b[A\xd8\x0eU\x8ee\x1c\xb3~D\x90o\x81\xeb'
	#	print("Need to decrypt")
		#This intext is then a ciphertext
		blokess = []
		prevDecrypt = IV

		#Split in 16 byte parts
		#The following need to be indented
		for i in range(0, len(intext), 16):
			ciph_block = intext[i:i+16]
			blokess.append(aes.xor_bytes(prevDecrypt, aes.decrypt_block(ciph_block)))
			prevDecrypt = ciph_block
			print("||", aes.unpad(b''.join(blokess)), "||" "Result from the for-loop")
		return aes.unpad(b''.join(blokess))

	else:
		#This intext is a plaintext
		intextt = (intext.encode('utf-8') + bytes(BLOCK_SIZE))[0:BLOCK_SIZE]
		zeroCipher = aes.encrypt_block(intextt)
		print(zeroCipher, "Result of encrypting using 0 padding")
		#print(intextt, "intext with 0 padding")
		#MUST ENCODE OR WONT LET YOU PAD!!!
		#print(intext, "This is the intext of length: ", len(intext))
		message = intext.encode('utf-8')
		#print(message, "This is the intext encoded of length: ", len(message))
		#pad the message
		paddedmessage = aes.pad(message)
		print(paddedmessage, "This is the padded message of length: ", len(paddedmessage))
		print(intextt, "This is the 0 padded message of length: ", len(intextt))
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
			print("||", b''.join(blokes), "||" "Result from the for-loop")
		return b''.join(blokes)


	#----------------------------------------------------------------


def main():
	aes = AES(bytes(KEY_SIZE))
	message = "hello world"
	decrypt = "decrypt"
	encrypt = "encrypt"
	ciphertext = b'\xa6\xbb\x1f~J5j\xc1p\xf2\x03\x04\\\xa96\x8e'
	ciphertextZero = b'\x0b[A\xd8\x0eU\x8ee\x1c\xb3~D\x90o\x81\xeb'
	crypt_cbc(aes, message, encrypt);

if __name__== '__main__':
	main()
