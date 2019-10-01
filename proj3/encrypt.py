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

def crypt_ecb(aes,intext):
	"""
	encrypts or decrypts text using AES object, in ECB mode
	"""

	# this is just a little test code. It only encrypts exactly one block,
	# using zero padding
	intext = (intext + bytes(BLOCK_SIZE))[0:BLOCK_SIZE]
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

		bintext = "Hello World"



main(sys.argv)
