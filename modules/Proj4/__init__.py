import string
import sys
import os
import argparse
import random

from Bozhu_AES import AES

#
# padding oracle for project 4,
# csc609/507-201
#
# author: burt
# date: 21 oct 2019
# last update: 21 oct 2019
# 
#

class Padding_Oracle:
	#key= a bytearray key, or None (the default). If none, a random key is created.
    #zero_padding= True or False. If False (the default) pkcs padding is used. else a non-standard zero padding is used.
   # norandomness= True or False (the default). If True, the IV's are always zero; and the key is 16 bytes of zeros using ///

	BlockSize = 16

	def __init__(self,key=None,zero_padding=False,norandomness=False):
		if norandomness:
			key = bytearray(self.BlockSize)
		elif key==None:
			key = bytearray(self.BlockSize)
			for i in range(self.BlockSize):
				key[i] = random.randint(0,255)
		else:
			# combination pad or truncate
			key = (bytes(key,encoding="utf-8")
				+bytes(self.BlockSize))[:self.BlockSize]  
				
		self.key = key
		self.aes = AES(key)
		self.zero_padding = zero_padding
		self.norandomness = norandomness

	def print_key(self):
		print(self.key)


	# ENCRYPTION

	def get_initial_vector(self):
		iv = bytearray(self.BlockSize)
		if self.norandomness:
			return iv
		for i in range(self.BlockSize):
			iv[i] = random.randint(0,255)
		return iv

	def encrypt_xor(self,ciphertext,plaintext,location):
		buf = bytearray(self.BlockSize)
		for i in range(self.BlockSize):
			buf[i] = plaintext[location+i] ^ ciphertext[location+i]
		return buf

	def encrypt(self,intext_ba):
		assert isinstance(intext_ba,bytearray),"encrypt parameter not a bytearray"

		# pad up
		pad_len = self.BlockSize - (len(intext_ba)%self.BlockSize)
		#print(pad_len)
		if not self.zero_padding: #Need the padding to not be 0 padding
			p = bytes([pad_len]*pad_len)
		else:
			p = bytes(pad_len)
        
		intext_ba += p
		assert (len(intext_ba)%self.BlockSize) == 0

		# initialize
		outtext_ba = bytearray(len(intext_ba)+self.BlockSize)
		location = 0
		outtext_ba[0:self.BlockSize] = self.get_initial_vector()
		

		for i in range(len(intext_ba)//self.BlockSize):

			buf = self.encrypt_xor(outtext_ba,intext_ba,location)
			#print(buf, 'buf  - encrypt')
			buf = self.aes.encrypt_block(buf)
			#print(buf, 'buf encrypted_block')
			location += self.BlockSize
			outtext_ba[location:location+self.BlockSize] = buf
		#print(outtext_ba)
		return outtext_ba


	# DECRYPTION

	def remove_padding(self,ba):
		i = int.from_bytes(ba[-1:],byteorder='big')
		if i<=0 or i>self.BlockSize:
			return ba
		return ba[:-i]

	def decrypt_xor(self,plaintext,ciphertext,buf,location):
		for i in range(self.BlockSize):
			plaintext[location+i] = buf[i] ^ ciphertext[location+i]

	def decrypt_only(self,intext_ba):
	
		assert isinstance(intext_ba,bytearray),"decrypt parameter not a bytearray"
		assert (len(intext_ba)%self.BlockSize and self.BlockSize>0) == 0, "decrypt text wrong length"

		# initialize
		outtext_ba = bytearray(len(intext_ba)-self.BlockSize) #All 0's?
		#print('\n',outtext_ba,len(outtext_ba), '\nouttext_ba\n') 
		location = 0

		for i in range(len(outtext_ba)//self.BlockSize):

			buf = intext_ba[location+self.BlockSize:location+2*self.BlockSize]
			#print(buf, 'buf - decrypt')
			buf = self.aes.decrypt_block(buf)
			#print(buf, 'buf decrypted_block')
			self.decrypt_xor(outtext_ba,intext_ba,buf,location)
			location += self.BlockSize
			#print(location) #Increases by 16
		return outtext_ba

	def decrypt(self,intext_ba):
		outtext_ba = self.decrypt_only(intext_ba)
		if not self.zero_padding:
			return self.remove_padding(outtext_ba)
		return outtext_ba


	# PADDING ORACLE

	def padding_oracle(self,intext_ba): #Returning True if padding is correct, False otherwise.
		#print('\n\n\n',intext_ba,'padding oracl intextBA', len(intext_ba),' \n\n\n' )
		ba = self.decrypt_only(intext_ba)
		#print(ba) #This is the decryption WITH the padding included. Formatted as a byte array
		#print(len(ba))
		i = int.from_bytes(ba[-1:],byteorder='big') #i is the padding. So 4 if \x04\x04\x04\x04
		#print('\n\n',i, '\n\n') # Returns 0 so makes sense that it returns false at the last.
		if i<=0 or i>self.BlockSize:
			return False
		return ba[-i:]==bytes([i]*i)
    



# end class
