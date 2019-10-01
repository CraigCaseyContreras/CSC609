#
# Adversarial Indistinguishability Experiment
# CSC507/609 Term 201
#
# Write an adversary with an advantage in the
# indistinguishability game for a vigenere cipher.
# The key is generated according to the distribution
# presented in problem 2.8 of the class text.
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

def vigenere_encipher(p,k):
	"""
	p is plaintext over the alphabet a, b, c, ... , z
	c is ciphertext over the alphabet A, B, C, ... , Z
	k is a string over the alphabet, the keyword, e.g. "keyword"
	"""
	if args_g.verbose:
		print("vigenere_encipher:")
		print("\tplaintext:",p)
		print("\tkey:",k)
	# Same vigenere code from the first project. Although used the professor's instead of mine.
	c = "";
	i = 0;
	for pi in p:
		x = ord(pi)-ord('a');
		j = ord(k[i].lower()) - ord('a');
		y = (x+j) % 26;
		c += chr(y+ord('A'));
		i += 1
		if i>= len(k):
			i = 0;
	return c;

def gen_key(n):

	#Picks random key of random size up until n and cannot be the same
	key = ""
	key_size = random.choice(range(1,n+1))
	alphabet = list(string.ascii_lowercase) #['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
	for i in range(key_size):
		new_letter = random.choice(alphabet)
		key += new_letter
		alphabet.remove(new_letter)

	return key


### Adversary functions

def gen_bit():
	return random.choice([0,1])

#returns messages
def adversary_challenge():
	m0 = 'aaa'
	m1 = 'abc'
	return (m0,m1)


def adversary_decision(m0, m1, c, k):
    # adversary takes the encryption c of
    # either m0 or m1 and returns a best
    # guess of which message was encrypted

	#The k was passed as a parameter to only get its length.
    guess = 0
    c = list(c)
    if k >= len(m0):
        guess = gen_bit()
    elif k < len(m0):
        if c[0] == c[-1] or c[0] == c[1]:
            guess = 0
        else:
            guess = 1
    return guess


# returns (m0,m1) from adversary challenge!!!
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
    k = gen_key(len(m[b]))  # the length of the first value in the tuple
    #print("Key: ", k)
    # the cipher is queried with key k and message m[b]
    # replace next line
    #print("m[b]: ", m[b])
    c = vigenere_encipher(m[b], k)
    #print("Cipher: ", c)
    #
    # the adversary makes its guess
    # replace next line
    guess = adversary_decision(m[0], m[1], c, len(k))
    #
    return b == guess


# FIRST RUNS 1000 times
def adversary_advantage(trials):
    if args_g.verbose:
        print("number trials:", trials)

    m = adversary_start()  # returns m0, m1 IS A TUPLE
    count = 0
    for i in range(trials):
        if adversary_sample(m):
            count += 1
    return (count + 0.0) / (trials + 0.0)


# main

def parse_args():
	parser = argparse.ArgumentParser(description="The adversary protocol game for a vigenre cipher.")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	parser.add_argument("-k", "--keyword", help="set keyword and trigger encryption mode")
	parser.add_argument("argument", help="depening on mode, either number of trials or the plaintext to encrypt ")
	
	return parser.parse_args()

def main(argv):
	global args_g
	args_g = parse_args()

	if args_g.keyword == None:
		print (adversary_advantage(int(args_g.argument)))
	else:
		print (vigenere_encipher(args_g.argument, args_g.keyword))


if __name__ == "__main__":
	main(sys.argv)




