import blowfish

bf = blowfish.Cipher(b'0123456789abcdef')
print(bf.decrypt_block(bf.encrypt_block(b'01234567')))


