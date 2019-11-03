import string
import sys
import os
import argparse

from Bozhu_AES import AES

#
# padding-attack.py
#
# author:
# date: 
# last update:
#
# template by: bjr oct 2019
# template update: 6 oct 2019
#

args_g = 0  # args are global

BLOCK_SIZE = 16  # the AES block size
KEY_SIZE = 16    # the AES key size

class PaddingOracle:

	def __init__(self,key):
		self.aes = AES(bytes(KEY_SIZE))
		
	def decrypt_cbc(c_text):
		p_text = c_text
		return p_text
		
	def check_padding(p_text):
		return True	
		
	def oracle(c_text):
		return check_padding(decrypt_cbc(c_text))
		
def padding_attack(padding_oracle,c_text):
	p_text = c_text
	return p_text

def parse_args():
	parser = argparse.ArgumentParser(description="Padding attack against ciphertext from stdin. ")
	parser.add_argument("key", help="encipherment key, for oracle use only")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

def main(argv):

	global args_g
	args_g = parse_args()

	## check args
	if args_g.verbose:
		print("command line arguments-")
		print("\t-v:", args_g.verbose)
		print("\tkey:", args_g.key)

	padding_oracle = PaddingOracle(args_g.key)
	try:
		bintext = sys.stdin.buffer.read()
		bintext = padding_attack(padding_oracle,bintext)
		sys.stdout.buffer.write(bintext)
	except Exception as e:
		print(e)
		pass

main(sys.argv)
