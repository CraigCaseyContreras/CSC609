#
# template author: bjr
# template date: 9 sept 2019


# please enter name and date: Craig Contreras
# student name: Craig Contreras
# date (last update): September 23, 2019

import argparse
import sys
import random
import string

### Encipherment and key generator functions
from typing import List, Any


def cycle_enigma_encipher(p,k):
	"""
	k is a list giving the permutation, e.g. [0,2,1]
	p is plaintext over an alphabet a, b, c, .. up to len(k) characters
	c is ciphertext over same alphabet but capital letters, A, B, C, ...

	"""
	if args_g.verbose:
		print("cycle_enigma_encipher:")
		print("\tplaintext:",p)
		print("\tkey:",k)

	#turns c into a list that has "p" stuff
	c = list(p)

	for i in range(len(p)):
		last_index = (ord(p[i]) - ord('a')) % len(k)
		for j in range(i+1):
			c[i] = chr(k[last_index] + ord('a'))
			last_index = k[last_index]
	return (''.join(c)).upper(); #joins them together and makes them uppercase

def gen_key(n):

# Just generates a random key of up untill length n. First numbers are appended, then they are shuffled to be random.
	key = []
	for i in range(0, n):
		key.append(i)
	random.shuffle(key)
	return key

def encode_alpha_key(k):
	return 	[ ord(kc)-ord('a') for kc in k ]

### Adversary functions

def gen_bit():
	return random.choice([0,1])


def adversary_challenge():
	# adversary chooses a message pair
	#
# replace next line
	m0 = 'aaabbbcccdddeeefff'
# replace next line
	m1 = 'dddeeefffaaabbbccc'
	#
	return (m0,m1)


def adversary_decision(m0,m1,c):

	#Here for each m0, m1, and c, there is a pair of 6 that is received for each one. That is used to compare to the cipher text
	# and eventually used to choose either m0 or m1.
	cipher_pair = []
	m0_pair = []
	m1_pair = []
	for i in range(0, len(c), 6):
		cipher_pair.append(''.join(set(c[i:i+6])))
		m0_pair.append(''.join(set(m0[i:i + 6])))
		m1_pair.append(''.join(set(m1[i:i + 6])))

	for i in range(0,6):
		if m0[i] in c[i]:
			guess = 0
		elif m1[i] in c[i]:
			guess = 1
		else:
			guess = gen_bit()

	return guess


def adversary_start():
	# adversary chooses a message pair
	return adversary_challenge()


def adversary_sample(m):
	# the adversarial indistinguishability experiment
	# a bit is chosen at random
	# replace next line
	b = gen_bit()
	#
	# a cipher key is chosen at random
	# replace next line
	key_size = len(set(m[b]))
	k = gen_key(key_size)  # the length of the first value in the tuple
	# print("Key: ", k)
	# the cipher is queried with key k and message m[b]
	# replace next line
	c = cycle_enigma_encipher(m[b], k)
	# print("Cipher: ", c)
	#
	# the adversary makes its guess
	# replace next line
	guess = adversary_decision(m[0], m[1], c.lower())
	#
	return b == guess


def adversary_advantage(trials):

	if args_g.verbose:
		print("number trials:", trials)

	m = adversary_start()
	count = 0 
	for i in range(trials):
		if adversary_sample(m):
			count += 1
	return (count+0.0)/(trials+0.0)

# main

def parse_args():
	parser = argparse.ArgumentParser(description="The adversary protocol game for a enigma-type cipher.")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	parser.add_argument("-k", "--keyword", help="set keyword and trigger encryption mode")
	parser.add_argument("argument", help="depening on mode, either number of trials or the plaintext to encrypt ")
	
	return parser.parse_args()

#
# the keyword given in the -k argument is a list of lower letter characters, for instance bcdefgha,
# with the following rules: 
#    1. A letter appears at most once
#    2. The letter a appears
#    3. If two letters appear then all the letters between those two letters in the alphabet apear.
#    4. If a letter does not appear in the keyword it must not appear in the plaintext
#
# turn the keyword into a list of numbers and this becomes the lookup array for the permutation (also called the key
# to the encryption). read the code of encode_alpha_key to make this clear.

def main(argv):
	global args_g
	args_g = parse_args()

	if args_g.keyword == None:
		print (adversary_advantage(int(args_g.argument)))
	else:
		print (cycle_enigma_encipher(args_g.argument, encode_alpha_key(args_g.keyword)))



if __name__ == "__main__":
	main(sys.argv)

