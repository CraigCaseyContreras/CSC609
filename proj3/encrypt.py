import string
import sys
import os
import argparse

from Bozhu_AES import AES

#
# encrypt.py
#
# author: Victoria Roddy
# date: 6 October 2019
# last update: 6 October 2019
# I WORKED WITH: Craig and Lucas
#
# template by: bjr sep 2019
# template update: 24 sep 2019
#

args_g = 0  # args are global

BLOCK_SIZE = 16  # the AES block size
KEY_SIZE = 16  # the AES key size


def pkcs_padding(plaintext):
    # CODE TAKEN FROM __init__.py file
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding


def remove_pkcs_padding(plaintext):
    # CODE TAKEN FROM __init__.py file
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message


def zero_padding(plaintext):
    padding_length = 16 - (len(plaintext) % 16)
    padding = bytes([0] * padding_length)
    return plaintext + padding


def remove_zero_padding(ciphertext):
    cipher_strip = ciphertext.strip(b'\x00')
    return cipher_strip


def iso_padding(plaintext):
    padding_length = 16 - (len(plaintext) % 16)
    padding = b'\x80' + bytes([0] * (padding_length-1))
    return plaintext + padding


def remove_iso_padding(plaintext):
    plain_strip = plaintext.strip(b'\x00')
    plain_strip2 = plain_strip.strip(b'\x80')
    return plain_strip2

def crypt_ecb(aes, intext):
 
    if args_g.decrypt:

        decryption_blocks = []
        block = [intext[i:i+16] for i in range(0, len(intext), 16)]
        for i in range(0, len(block)):
            ciph_block = block[i]
            decryption_blocks.append(aes.decrypt_block(ciph_block))
            result = b''.join(decryption_blocks)
        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(result)
        elif args_g.padding == "zero":
            output = remove_zero_padding(result)
        elif args_g.padding == "iso":
            output = remove_iso_padding(result)
        else:
            output = remove_pkcs_padding(result)

    else:

        # do encryption
        blobs = []
        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16]
            res = aes.encrypt_block(ptBlocks)
            blobs.append(res)
        output = b''.join(blobs)
        
    return output

def crypt_cntr(aes, intext):
    IV = os.urandom(16)

    if args_g.decrypt:

        decryption_blocks = []
        block = [intext[i:i + 16] for i in range(0, len(intext), 16)]
        IV = block[0]
        block.pop(0)
        iv_block = IV
        for i in range(0, len(block)):
            ciph_block = block[i]
            jul = aes.encrypt_block(iv_block)
            decryption_blocks.append(aes.xor_bytes(jul, ciph_block))

            # INCREMENTS COUNTER BY +1
            iv_int = int.from_bytes(iv_block, "big")
            iv_int_inc = iv_int + 1
            iv_block = iv_int_inc.to_bytes(16, byteorder="big")

        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(b''.join(decryption_blocks))
        elif args_g.padding == "zero":
            output = remove_zero_padding(b''.join(decryption_blocks))
        elif args_g.padding == "iso":
            output = remove_iso_padding(b''.join(decryption_blocks))
        else:
            output = remove_pkcs_padding(b''.join(decryption_blocks))
    
    else:

        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        blobs = []
        iv_block = IV
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16]
            encrypt_iv = aes.encrypt_block(iv_block)
            block = aes.xor_bytes(encrypt_iv, ptBlocks)
            blobs.append(block)

            # INCREMENTS COUNTER BY +1
            iv_int = int.from_bytes(iv_block, "big")
            iv_int_inc = iv_int + 1
            iv_block = iv_int_inc.to_bytes(16, byteorder="big")

        blobs.insert(0, IV)
        output = b''.join(blobs)

    return output

def crypt_cbc(aes, intext):
    IV = os.urandom(16)

    if args_g.decrypt:

        decryption_blocks = []
        block = [intext[i:i + 16] for i in range(0, len(intext), 16)]
        iv_block = block[0]
        block.pop(0)
        # Splits in 16-byte parts.
        for i in range(0, len(block)):
            ciph_block = block[i]
            decryption_blocks.append(aes.xor_bytes(iv_block, aes.decrypt_block(ciph_block)))
            iv_block = ciph_block
            result = b''.join(decryption_blocks)
        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(result)
        elif args_g.padding == "zero":
            output = remove_zero_padding(result)
        elif args_g.padding == "iso":
            output = remove_iso_padding(result)
        else:
            output = remove_pkcs_padding(result)
        #return output

    else:

        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        blobs = []
        xor_block = IV
        # Splits in 16-byte parts.
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16]
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            blockCT = aes.encrypt_block(aes.xor_bytes(ptBlocks, xor_block))
            blobs.append(blockCT)
            last_ciphertext = blockCT
        blobs.insert(0, IV)
        output = b''.join(blobs)

    return output

def crypt_ofb(aes, intext):
    iv = os.urandom(16)

    if args_g.decrypt:

        decryption_blocks = []
        # splits cipher test into blocks of size 16
        block = [intext[i:i + 16] for i in range(0, len(intext), 16)]
        iv_block = block[0]
        block.pop(0)
        # Splits in 16-byte parts.
        for i in range(0, len(block)):
            ciphertext_block = block[i]
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            # decryption_blocks.append(aes.xor_bytes(iv_block, aes.decrypt_block(iv_block)))
            encrypted_iv = aes.encrypt_block(iv_block)
            iv_block = encrypted_iv
            decryption_blocks.append(aes.xor_bytes(encrypted_iv, ciphertext_block))
            result = b''.join(decryption_blocks)
        if args_g.padding == "pkcs":
            output = remove_pkcs_padding(b''.join(decryption_blocks))
        elif args_g.padding == "zero":
            output = remove_zero_padding(b''.join(decryption_blocks))
        elif args_g.padding == "iso":
            output = remove_iso_padding(b''.join(decryption_blocks))
        else:
            output = remove_pkcs_padding(b''.join(decryption_blocks))
       
    else:

        if args_g.padding == "pkcs":
            padded_messg = pkcs_padding(intext)
        elif args_g.padding == "zero":
            padded_messg = zero_padding(intext)
        elif args_g.padding == "iso":
            padded_messg = iso_padding(intext)
        else:
            padded_messg = pkcs_padding(intext)
        blobs = []
        xor_block = iv
        
        for i in range(0, len(padded_messg), 16):
            ptBlocks = padded_messg[i:i + 16]
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            jul = aes.encrypt_block(xor_block)
            xor_block = jul
            block = aes.xor_bytes(xor_block, ptBlocks)
            blobs.append(block)
        blobs.insert(0, iv)
        output = b''.join(blobs)

    return output


def crypt_func(aes, intext, mode):
    output = b''
    if mode == "ecb":
        output = crypt_ecb(aes, intext)
    elif mode == "cbc":
        output = crypt_cbc(aes, intext)
    elif mode == "ofb":
        output = crypt_ofb(aes, intext)
    elif mode == "cntr":
        output = crypt_cntr(aes, intext)
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


modes = ["ecb", "cbc", "ofb", "cntr"]
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
