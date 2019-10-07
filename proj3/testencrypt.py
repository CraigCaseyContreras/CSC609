import random
import string
import sys
import os
import argparse
import testClasses as pyaes
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

def _concat_list(a,b):
	return a + bytes(b)

#PADDINGS!!!

#This is the ISO padding
def iso_padding(plaintext):
    pad_length = 16-(len(plaintext)%16)
    pad = b'\x80' + bytes([0] * (pad_length -1))
    return plaintext + pad

def remove_iso_padding(plaintext):
    stripper = plaintext.strip(b'\x00')
    second_stripper = stripper.strip(b'\x80')
    return second_stripper

#This is the 0 padding
def zero_pading(plaintext):
    pad_length = 16-(len(plaintext)%16)
    pad = b'\x00' + bytes([0] * (pad_length -1))
    return plaintext + pad

def remove_zero_padding(plaintext):
    stripper = plaintext.strip(b'\x00')
    return stripper

#This is the PkCS #7 padding
def pkcs_padding(aes, plaintext):
    pad_message = aes.pad(plaintext)
    return pad_message

def remove_pkcs(aes, plaintext):
    unpadded_message = aes.unpad(plaintext)
    return unpadded_message
#-------------------------------------------

def crypt_cbc(aes, intext, mode): #Have to fix the professors!!!
    if mode == "decrypt":
        return "hellow"
    else:
        return "cool"
	#----------------------------------------------------------------

#---------------------------------------------------


class Counter(object):
    '''A counter object for the Counter (CTR) mode of operation.'''

    def __init__(self, init_value = 1):
        # Convert the value into an array of bytes long
        self._counter = [ ((init_value >> i) % 256) for i in range(128 - 8, -1, -8) ]

    value = property(lambda s: s._counter)

    def increment(self):
        '''Increment the counter (overflow rolls back to 0).'''
        for i in range(len(self._counter) - 1, -1, -1):
            self._counter[i] += 1
            if self._counter[i] < 256: break
            # Carry the one
            self._counter[i] = 0
        # Overflow
        else:
            self._counter = [ 0 ] * len(self._counter)

#----------------------------------------------------

def crypt_cntr(aes, intext, mode):

	# Stream cipher so no need to pad!!!

	if mode == "decrypt":
		counter = Counter()
		remaining_counter = []
		while len(remaining_counter) < len(intext):
			remaining_counter  += aes.encrypt_block(counter.value)
			counter.increment()

		#pt = intext.encode('utf-8') #USE ONLY WHEN HAVE PLAINTEXT
		pt = bytearray(intext) #USE WHEN HAVE THE CIPHERTEXT!!!
		decrypted = aes.xor_bytes(pt, remaining_counter) #[ (p ^ c) for (p, c) in zip(pt, remaining_counter) ]
		remaining_counter = remaining_counter[len(decrypted):]
		pt = decrypted.decode()
		print(pt, "Result from cntr- decrypt")
		#print(decrypted, "Result from the cntr - decrypt")
		return pt

	else:
		counter = Counter()
		remaining_counter = []
		while len(remaining_counter) < len(intext):
			remaining_counter  += aes.encrypt_block(counter.value)
			counter.increment()

		pt = intext.encode('utf-8') #USE ONLY WHEN HAVE PLAINTEXT
		#pt = bytearray(intext) #USE WHEN HAVE THE CIPHERTEXT!!!
		encrypted = aes.xor_bytes(pt, remaining_counter) #[ (p ^ c) for (p, c) in zip(pt, remaining_counter) ]
		remaining_counter = remaining_counter[len(encrypted):]
		print(encrypted, "Result from the cntr - encrypt")
		return encrypted

def main():

	aes = AES(bytes(KEY_SIZE))
	message = "My name is Craig Contreras."
	decrypt = "decrypt"
	encrypt = "encrypt"
	ciphertextCBC = crypt_cbc(aes, message, encrypt)
	#messageCBC = crypt_cbc(aes, ciphertextCBC, decrypt)
	ciphertextCNTR = crypt_cntr(aes, message, encrypt)
	messageCNTR = crypt_cntr(aes, ciphertextCNTR, decrypt)
	iso_mess = iso_padding(b'Hello World')
	print(iso_mess, len(iso_mess))
	deiso = remove_iso_padding(iso_mess)
	print(deiso)
	zero_mess = zero_pading(b'hello ghjghjgjgjhghjgjjhgkjhworld')
	print(zero_mess, len(zero_mess))
	dezero = remove_zero_padding(zero_mess)
	print(dezero)
	pkmess = pkcs_padding(aes, b'hello wjhgjgorld')
	print(pkmess, len(pkmess))
	#test_ofb(aes, message)
	# messageOFB = crypt_ofb(aes, message, encrypt)
	# ciphertextOFB = crypt_ofb(aes, messageOFB, decrypt)

if __name__== '__main__':
	main()
