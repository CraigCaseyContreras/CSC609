import string
import sys
import os
import argparse
import numpy

#
# crack-vigenere.py
#
# author: Craig Contreras
# date: Sept 6. 2019
# last update:
# template by: bjr aug 2019
#

args_g = 0  # args are global

def frequencycount(s):
	count = [0] * 26
	for c in s :
		i = ord(c.lower())-ord('a')
		count[i] += 1
	return count

def get_statistics(filename):
	f = open(filename,"r")
	p = "" ;
	for line in f:
		for c in line :
			if c.isalpha() :
				p = p + c.lower() ;
	f.close() ;
	return frequencycount(p) ;
	
def get_transpose(c, k_len):
	blocks = []
	for i in range(k_len):
		block = ''
		for j in range(i, len(c), k_len):
			block = block + c[j]
		blocks.append(block)
	return blocks

def make_group (c, k_len, ref_stat):
	fc_list = []
	key_list = []
	maxi = -1
	for a in range(0, k_len):
		key = c [a :: k_len]
		freq_ct = frequencycount(key)
		
		for i in range(0, 26):
			fc_dot = numpy.dot(numpy.roll(ref_stat, i), freq_ct)	
			fc_list.append(fc_dot)
			maxi = numpy.argmax(fc_list)
		key_list.append(maxi)
		fc_list = []
	return (key_list)
		
def find_key (ckey):
	key_1 = ""
	for a in ckey:
		p = a + ord('a')
		key_1 = key_1 + chr(p)
	return (key_1)
		

def parse_args():
	parser = argparse.ArgumentParser(description="Cracks a vigenere cipher by freqency analysis, given the key length.")
	parser.add_argument("key_length", type=int, help="the presumed length of the encipherment key")
	parser.add_argument("reference_text", help="a text file sampling the letter frequence statistics")
	parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
	return parser.parse_args()

def main(argv):

	global args_g
	args_g = parse_args()

	fc = get_statistics(args_g.reference_text)
	if args_g.verbose:
		print (fc)

	## gather plain text and format
	t_in = ""
	for line in sys.stdin:
		for c in line:
			if c.isalpha():
				t_in += c

	if args_g.verbose:
		print (t_in)

	#
	# code
	#
	gru = make_group (t_in, args_g.key_length, fc)

	password = find_key(gru)
	print(password)


main(sys.argv)
