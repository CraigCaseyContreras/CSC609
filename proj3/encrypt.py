import string
import sys
import os
import argparse

from Bozhu_AES import AES

#
# encrypt.py
#
# author: Craig Contreras
# date: October 7 2019
# last update: October 7 2019
# Attributions: Victoria, Lucas, Kataryzyna
#
# template by: bjr sep 2019
# template update: 24 sep 2019
#

args_g = 0  # args are global

BLOCK_SIZE = 16  # the AES block size
KEY_SIZE = 16  # the AES key size


#Does pkcs padding calling onto AES
def pkcs_padding(aes, plaintext):
    padded_messg = aes.pad(plaintext)
    return padded_messg

#Unpads pkcs padding
def remove_pkcs_padding(aes, ciphertext):
    unpadded_messg = aes.unpad(ciphertext)
    return unpadded_messg

#generates a random IV of size 16
def generate_iv(BLOCK_SIZE):
    iv = os.urandom(BLOCK_SIZE)
    return iv

#Does zero padding
def zero_padding(plaintext):
    pad_length = 16 - (len(plaintext) % 16)
    pad = bytes([0] * pad_length)
    return plaintext + pad

#Removes zero padding
def remove_zero_padding(ciphertext):
    zero_strip = ciphertext.strip(b'\x00')
    return zero_strip

#Does iso padding
def iso_padding(plaintext):
    pad_length = 16 - (len(plaintext) % 16)
    pad = b'\x80' + bytes([0] * (pad_length-1))
    return plaintext + pad

#Removes iso padding
def remove_iso_padding(ciphertext):
    zero_strip = ciphertext.strip(b'\x00')
    eightzero_strip = zero_strip.strip(b'\x80')
    return eightzero_strip

def crypt_ecb(aes, intext):
 
    if args_g.decrypt:

        decryption_blocks = []
        block = [intext[i:i+16] for i in range(0, len(intext), 16)] #makes the block
        
        for i in range(0, len(block)):
            ciph_block = block[i] #The ciph block
            decrypted_block = aes.decrypt_block(ciph_block) #decrypts the ciph block
            decryption_blocks.append(decrypted_block) #Adds to the decrypted blocks
            result = b''.join(decryption_blocks) #Puts them together
        
        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(aes, result)
        elif args_g.padding == "zero":
            output = remove_zero_padding(result)
        elif args_g.padding == "iso":
            output = remove_iso_padding(result)
        else:
            output = remove_pkcs_padding(aes, result)

    else:

        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(aes, intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        
        blobs = []
        
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16] #Gets set of 16
            res = aes.encrypt_block(ptBlocks) #encrypts the set
            blobs.append(res) #Adds to the blob
        output = b''.join(blobs) #Puts them together
        
    return output

def crypt_cntr(aes, intext):
    IV = generate_iv(BLOCK_SIZE)

    if args_g.decrypt:

        decryption_blocks = []
        block = [intext[i:i + 16] for i in range(0, len(intext), 16)] #Gets the block
        IV = block[0] #IV gotten from first element
        block.pop(0) #First element popped
        iv_block = IV #Iv block is the IV
        
        for i in range(0, len(block)):
            ciph_block = block[i] #The cipher block
            jul = aes.encrypt_block(iv_block) #Encrypts to decrypt because symmetric
            xored_result = aes.xor_bytes(jul, ciph_block)
            decryption_blocks.append(xored_result) #XORs first then appends to the blocks
            result = b''.join(decryption_blocks) #Puts them together

            # INCREMENTS COUNTER BY +1
            iv_integer = int.from_bytes(iv_block, "big") #Gets an integer from the IV
            iv_integer_increase = iv_integer + 1 #Adds one to the counter
            iv_block = iv_integer_increase.to_bytes(16, byteorder="big") #Returns IV to its bytes

        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(aes, result)
        elif args_g.padding == "zero":
            output = remove_zero_padding(result)
        elif args_g.padding == "iso":
            output = remove_iso_padding(result)
        else:
            output = remove_pkcs_padding(result)
    
    else:

        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(aes, intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        
        blobs = []
        iv_block = IV
        
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16] #Gets a set of 16 or a block
            encrypt_iv = aes.encrypt_block(iv_block) #Encrypts
            block = aes.xor_bytes(encrypt_iv, ptBlocks) #XORs
            blobs.append(block) #Adds to the blob

            # INCREMENTS COUNTER BY +1
            iv_integer = int.from_bytes(iv_block, "big") #Gets an integer from the IV
            iv_integer_increase = iv_integer + 1 #Adds 1 to the counter
            iv_block = iv_integer_increase.to_bytes(16, byteorder="big") #Returns the IV into the bytes

        blobs.insert(0, IV) #Stores IV at the beginning for decryption
        output = b''.join(blobs) #Joins together

    return output

def crypt_cbc(aes, intext):
    IV = generate_iv(BLOCK_SIZE) #generates random IV of size 16

    if args_g.decrypt:

        decryption_blocks = []
        block = [intext[i:i + 16] for i in range(0, len(intext), 16)] #Gets the intext and makes it into the blocks
        iv_block = block[0] #Gets the IV that was stored
        block.pop(0) #Pops the IV out
        # Splits in 16-byte parts
        
        for i in range(0, len(block)):
            ciph_block = block[i]
            decrypted_block = aes.decrypt_block(ciph_block)
            decryption_blocks.append(aes.xor_bytes(iv_block, decrypted_block)) #Uses the IV to start decrypting
            iv_block = ciph_block #Now just cycles through the blocks to decrypt
            result = b''.join(decryption_blocks)
        
        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(aes, result)
        elif args_g.padding == "zero":
            output = remove_zero_padding(result)
        elif args_g.padding == "iso":
            output = remove_iso_padding(result)
        else:
            output = remove_pkcs_padding(result)
        #return output

    else:

        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(aes, intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        
        blobs = []
        xor_block = IV
        # Splits in 16-byte parts
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16] #Gets in sets of 16
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            blockCT = aes.encrypt_block(aes.xor_bytes(ptBlocks, xor_block)) #XORs the IV and the plaintext block
            blobs.append(blockCT) #Adds to the blob 
            xor_block = blockCT #Cycles through to encrypt
        blobs.insert(0, IV) #Stores the IV into the first element of the blob array
        output = b''.join(blobs)

    return output

def crypt_ofb(aes, intext):
    iv = generate_iv(BLOCK_SIZE) #generates IV

    if args_g.decrypt:

        decryption_blocks = []
        # splits cipher test into blocks of size 16
        block = [intext[i:i + 16] for i in range(0, len(intext), 16)] #Gets the intext and makes it into the blocks
        iv_block = block[0] #Gets the IV that was stored
        block.pop(0) #Pops the IV out
        # Splits in 16-byte parts.
        for i in range(0, len(block)):
            ciphertext_block = block[i] #the ciph block
            encrypted_iv = aes.encrypt_block(iv_block) #Encrypts the IV block because symmetric
            iv_block = encrypted_iv
            xored_result = aes.xor_bytes(encrypted_iv, ciphertext_block) #XORs the encrypted iv and the ciph block
            decryption_blocks.append(xored_result) #Adds the XORed result 
            result = b''.join(decryption_blocks) #Puts them together
        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(aes, result)
        elif args_g.padding == "zero":
            output = remove_zero_padding(result)
        elif args_g.padding == "iso":
            output = remove_iso_padding(result)
        else:
            output = remove_pkcs_padding(result)
       
    else:

        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(aes, intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        
        blobs = []
        xor_block = iv
        
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16] #Gets a block
            jul = aes.encrypt_block(xor_block) #Jul (for Julia) is the encryppted block
            xor_block = jul #Not sure if needed or can do directly?
            block = aes.xor_bytes(xor_block, ptBlocks) #XORs the xor block and the plaintext block
            blobs.append(block) #Adds to blob
        blobs.insert(0, iv) #Inserts IV at beginning for use to decrypt
        output = b''.join(blobs) #Puts them together

    return output


def crypt_func(aes, intext, mode):
    output = b''
    if mode == "ecb":
        output = crypt_ecb(aes, intext)
    elif mode == "cntr":
        output = crypt_cntr(aes, intext)
    elif mode == "cbc":
        output = crypt_cbc(aes, intext)
    elif mode == "ofb":
        output = crypt_ofb(aes, intext)
    return output


def parse_args():
    parser = argparse.ArgumentParser(description="Encrypt/decrypt stdin. ")
    parser.add_argument("key", help="encipherment key")
    parser.add_argument("-d", "--decrypt", action="store_true", help="decrypt, instead of encrypting")
    parser.add_argument("-m", "--mode", help="mode either cntr (default), cbc, ofb, or ecb")
    parser.add_argument("-n", "--nonce", help="the initial vector, as ascii. omit for a random nonce (recommended)")
    parser.add_argument("-p", "--padding", help="padding either pkcs (default), iso, or zero")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose")
    return parser.parse_args()


modes = ["cntr", "cbc", "ofb", "ecb"]
pads = ["pkcs", "iso", "zero"]


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
    try:
        bintext = sys.stdin.buffer.read()
        bintext = crypt_func(aes, bintext, args_g.mode)
        sys.stdout.buffer.write(bintext)
    except Exception:
        pass


main(sys.argv)
