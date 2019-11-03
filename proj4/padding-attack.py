import string
import sys
import os
import argparse

from Proj4 import Padding_Oracle

#
# padding-attack.py
#
# author:
# date: 
# last update:
#
# template by: bjr oct 2019
# template update: 22 oct 2019
#

args_g = 0  # args are global
BLOCK_SIZE = 16


#Also manipulates to find out where would we get an invalid padding
# def findPaddingbytes(oracle, intext):
# 	blocks = [intext[i:i+16] for i in range(0, len(intext), 16)]
# 	penultimate_block = blocks[-2]
# 	testing_block = bytearray(len(penultimate_block))
# 	testing_block[:] = penultimate_block

# 	for l in range(len(penultimate_block)):
# 		penultimate_block[l] = penultimate_block[l] + 1
# 		modified_byte = bytearray(len(intext))
# 		modified_byte[:] = intext
# 		modified_byte[-2 * len(penultimate_block): -len(penultimate_block)] = penultimate_block
# 		if oracle.padding_oracle(modified_byte):
# 			print('VALID PADDING')
# 		else:
# 			print('INVALID PADDING')
# 			return(len(penultimate_block) - l) #Returns where. So if '4', then the padding is length of 4.
# 		penultimate_block[:] = testing_block

def attack_mode(oracle,intext):
	print(oracle.padding_oracle(intext)) #Prints out false - so bad padding!!
	if oracle.padding_oracle(intext) == False:
		print('INVALID PADDING')
		print('CRACKING.....')
		plaintext = attackCipher(oracle, intext)
		sys.stdout.buffer.write(str.encode(plaintext))

	else:
		print('VALID PADDING')


def attackCipher(oracle, intext):
	fake_cipher = [0]*16
	plaintext = [0]*16
	current = 0
	message = ''

	#Gets the amount of blocks
	number_of_blocks = int(len(intext)/BLOCK_SIZE)
	#Makes little 'sub-blocks'
	blocks = [[]] * number_of_blocks
	for i in range(number_of_blocks):
		blocks[i] = intext[i * BLOCK_SIZE: (i+1) * BLOCK_SIZE]	

	#calculate # of blocks for each msg.
	for l in range(len(blocks)-1): 
		#the length of each block is 16. Start by 1 because i increment
		for iteration in range(1,17):
			for ju in range(256):
				fake_cipher[-iteration]=ju
				print(fake_cipher, 'FAKE CIPHER')
				if oracle.padding_oracle(bytearray(fake_cipher)+blocks[l+1]):
					current = iteration
					print(current, 'CURRENT')
					plaintext[-iteration] = ju^iteration^blocks[l][-iteration]
					print(plaintext, 'PLAINTEXT')
			for w in range(1, current+1):
				#for decode the second byte I must set the previous bytes with 'itera+1'
				fake_cipher[-w] = plaintext[-w]^iteration+1^blocks[l][-w]
				print(plaintext[-w], 'PT -W')
				print(iteration, 'ITERATION')
				print(blocks[l][-w], 'BLOCKS L -W')
		for k in range(16):
			if plaintext[k] >= 32:
				char = chr(int(plaintext[k]))
				message += char
	return message

	
def encrypt_mode(oracle,intext):
	#print(intext)
	outtext = oracle.encrypt(intext)
	sys.stdout.buffer.write(outtext)
	
def decrypt_mode(oracle,intext):
	#funciton that goes outside??#
	outtext = oracle.decrypt(intext)
	sys.stdout.buffer.write(outtext)



# first one on the list is the default
modes = ["encrypt","decrypt","attack"]
# callout table
modes_f = { "encrypt":encrypt_mode, "decrypt":decrypt_mode, "attack":attack_mode}


def parse_args():
	parser = argparse.ArgumentParser(description="Padding attack against ciphertext from stdin. ")
	parser.add_argument("key", help="encipherment key, for oracle use only")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	parser.add_argument("-m", "--mode", help="mode either encrypt, decrypt, or attack")	
	parser.add_argument("-R", "--norandomness", action="store_true", help="set IV and key to zero (key argument required but ignored)")	
	parser.add_argument("-z", "--zero", action="store_true", help="use zeros padding")	
	return parser.parse_args()

def main(argv):

	global args_g
	args_g = parse_args()
	if args_g.mode not in modes:
		args_g.mode = modes[0]
	
	padding_oracle = Padding_Oracle(key= args_g.key, zero_padding=args_g.zero, 
		norandomness=args_g.norandomness)
	bintext = bytearray(sys.stdin.buffer.read())
	modes_f[args_g.mode](padding_oracle,bintext)


main(sys.argv)
