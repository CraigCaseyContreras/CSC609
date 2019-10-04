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

def _concat_list(a,b):
	return a + bytes(b)

def crypt_ofb(aes, intext):

	return

#-------------------------------------------

def crypt_cbc(aes, intext, mode):
	#our intext right now is "hello world" so really all we have is "hello world" as the paramter
	#intext can also be a ciphertext so can be either one
	#if args.v.encrypt, intext is a plaintext,
	#if args.v.decrypt, intext is a ciphertext
	# Get the IV
	IV = b'\01' * 16
	#print(IV, "This is the IV of length: ", len(IV))

	if mode == "decrypt":
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
		stringer = aes.unpad(b''.join(blokess))
		#print(blokess) # blocks are working
		print (stringer.decode('utf-8'), "Result from the CBC - decrypt")
		return stringer.decode('utf-8')

	else:
		#This intext is a plaintext
		#intextt = (intext.encode('utf-8') + bytes(BLOCK_SIZE))[0:BLOCK_SIZE]
		#zeroCipher = aes.encrypt_block(intextt)
		#print(zeroCipher, "Result of encrypting using 0 padding")

		#print(intextt, "intext with 0 padding")
		#MUST ENCODE OR WONT LET YOU PAD!!!
		#print(intext, "This is the intext of length: ", len(intext))
		message = intext.encode('utf-8')
		message = bytearray(message)
		#print(message, "This is the intext encoded of length: ", len(message))
		#pad the message
		paddedmessage = aes.pad(message)
		#print(paddedmessage, "This is the padded message of length: ", len(paddedmessage))
		#print(intextt, "This is the 0 padded message of length: ", len(intextt))
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
			prev = bloke
		#print(blokes[0], len(blokes[0])) #Blocks are working!!!
		joinedBlockes = b''.join(blokes)
		print(joinedBlockes, "Result from CBC - encrypt")
		return joinedBlockes
	#----------------------------------------------------------------

# def crypt_cfb(aes, intext, mode):
#
# 	IV = b'\01' * 16
#
# 	if mode == "decrypt":
# 		shift_done = IV
# 		decrypted = []
# 		for j in range(0, len(intext), 16):
# 			cipher_segment = intext[j:j+16]
# 			xor_segment = aes.encrypt_block(shift_done)[:len(cipher_segment)]
# 			pt_segment = aes.xor_bytes(cipher_segment, xor_segment)
# 			shift_done = _concat_list(shift_done[len(cipher_segment):], cipher_segment)
# 			decrypted.append(pt_segment)
# 		print(b''.join(decrypted), "||" "Result from the CFB - decrypt")
# 		return (b''.join(decrypted))
#
# 	else:
# 		message = intext.encode('utf-8')
# 		shift_done = IV
# 		# pad the message
# 		#paddedmessage = aes.pad(message)
# 		encrypted = []
# 		for i in range(0, len(message), 16):
# 			pt_segment = message[i: i + 16]
# 			xor_segment = aes.encrypt_block(shift_done)[:len(pt_segment)]
# 			cipher_segment = aes.xor_bytes(pt_segment, xor_segment)
#
# 			shift_done = _concat_list(shift_done[len(cipher_segment):], cipher_segment)
# 			encrypted.append(cipher_segment)
# 		print(b''.join(encrypted), "||" "Result from the CFB - encrypt")
# 		return (b''.join(encrypted))


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
	message = "My name is Craig Contreras. Attack can commence."
	decrypt = "decrypt"
	encrypt = "encrypt"
	ciphertextCBC = crypt_cbc(aes, message, encrypt)
	messageCBC = crypt_cbc(aes, ciphertextCBC, decrypt)
	ciphertextCNTR = crypt_cntr(aes, message, encrypt)
	messageCNTR = crypt_cntr(aes, ciphertextCNTR, decrypt)

if __name__== '__main__':
	main()


