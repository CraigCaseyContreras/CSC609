import string
import sys
import os
import argparse

#
# vigenere.py
#
# author: Craig Contreras
# date: September 9, 2019
# last update:
# template by: bjr aug 2019
#

args_g = 0  # args are global


def vigenere_encipher(p,k):
	c = ""
	x=0
	while x<len(p):
			d = ((ord(k[x]) + ord(p[x]) - 2 * ord('a')) % 26) + ord('A')
			c =c + chr(d)
			if len(k)<len(p):
				k = k + k
			x = x + 1				
	return c ;
	
def vigenere_decipher(c,k):
	p = ""
	k=k.upper()
	x=0
	while x<len(c):
		a = ((ord(c[x]) - ord(k[x])))
		if a<0:
			a = a + 26
		a = a + ord('a')
		p = p + chr(a)
		if len(k)<len(c):
			k = k + k
		x = x + 1		
	return p ;
    
def parse_args():
	parser = argparse.ArgumentParser(description="Encrypt/decrypt stdin by a vigenere cipher. Ignores any character other than alphabetic.")
	parser.add_argument("key", help="encipherment key")
	parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt, instead of encrypting")
	parser.add_argument("-g", "--word_group", type=int, default=5, help="characters per word group")
	parser.add_argument("-G", "--line_group", type=int, default=5, help="word groups per line")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

def main(argv):

	global args_g
	args_g = parse_args()

	## gather plain text and format
	t_in = ""
	for line in sys.stdin:
		for c in line:
			if c.isalpha():
				if not args_g.decrypt:
					c = c.lower()
				else:
					c = c.upper()
				t_in += c
 
	## encrypt/decrypt
	if args_g.decrypt:
		t_out = vigenere_decipher(t_in,args_g.key)
	else:
		t_out = vigenere_encipher(t_in,args_g.key)

	## pretty print ct
	i = 0
	s = ""
	r = args_g.word_group * args_g.line_group

	for c in t_out:
		s += c
		i += 1
		if i%args_g.word_group==0:
			s += ' '
		if i%r==0:
			s += '\n'
	print (s)
	

main(sys.argv)

