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

def crypt_cbc(aes, intext):

	IV = b'\01' * 16

	if args_g.decrypt:
		#This intext is then a ciphertext
		blokess = []
		prevDecrypt = IV

		#Split in 16 byte parts
		#The following need to be indented
		for i in range(0, len(intext), 16):
			ciph_block = intext[i:i+16]
			blokess.append(aes.xor_bytes(prevDecrypt, aes.decrypt_block(ciph_block)))
			prevDecrypt = ciph_block
		outext = aes.unpad(b''.join(blokess))

	else:
		#This intext is a plaintext
		#MUST ENCODE OR WONT LET YOU PAD!!!

		message = (intext.encode('utf-8'))
		message = bytearray(message)

		#pad the message
		paddedmessage = aes.pad(message)
		#The code does the encrypt WITH the xor at the same time

		blokes = []
		prev = IV

		#Now we have to split into 16-byte parts
		for l in range(0, len(paddedmessage), 16):
			paddedBlock = paddedmessage[l:l+16]
			#CBC mode so XOR the block with before
			bloke = aes.encrypt_block(aes.xor_bytes(paddedBlock, prev))
			blokes.append(bloke)
			prev = bloke
		#print(blokes[0], len(blokes[0])) #Blocks are working!!!
		outext = b''.join(blokes)
	return outext

def crypt_ecb(aes,intext):
	"""
	encrypts or decrypts text using AES object, in ECB mode
	"""

	# this is just a little test code. It only encrypts exactly one block,
	# using zero padding
	intext = (intext + bytes(BLOCK_SIZE))[0:BLOCK_SIZE]
	print(intext, "HAHAHA")
	assert(len(intext)==BLOCK_SIZE)

	if args_g.decrypt:
	# do decryption
		outtext = aes.decrypt_block(intext)

	else:
	#do encryption
		outtext = aes.encrypt_block(intext)

	return outtext




def parse_args():
	parser = argparse.ArgumentParser(description="Encrypt/decrypt stdin. ")
	parser.add_argument("key", help="encipherment key")
	parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt, instead of encrypting")
	parser.add_argument("-m", "--mode", help="mode either cntr (default), cbc, ofb, or ecb")
	parser.add_argument("-n", "--nonce", help="the initial vector, as ascii. omit for a random nonce (recommended)")
	parser.add_argument("-p", "--padding", help="padding either pkcs (default), iso, or zero")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

modes = ["cntr","cbc","ofb","cntr"]
pads = ["pkcs","iso","zero"]

def main(argv):

	global args_g
	args_g = parse_args()

	if args_g.mode not in modes:
		args_g.mode = modes[0]
	if args_g.padding not in pads:
		args_g.padding = pads[0]

	## check args
	if args_g.verbose:
		print("command line arguments-")
		print("\t-d:", args_g.decrypt)
		print("\t-m:", args_g.mode)
		print("\t-n:", args_g.nonce)
		print("\t-p:", args_g.padding)
		print("\t-v:", args_g.verbose)
		print("\tkey:", args_g.key)

	aes = AES(bytes(KEY_SIZE))

	try:
		bintext = sys.stdin.buffer.read()
		#print(bintext, "+++bintext1")
		bintext = crypt_ecb(aes,bintext)
		#print(bintext)
		#print(bintext, "+++bintext2 of length: ", len(bintext))
		sys.stdout.buffer.write(bintext)
	except Exception:
		pass


main(sys.argv)
