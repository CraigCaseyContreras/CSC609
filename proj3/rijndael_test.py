#import sys
#sys.path.append('../../class/modules')
from Bozhu_AES import AES

baes = AES(b'0123456789abcdef')
ct = baes.encrypt_block(b'0123456789abcdef')
print(baes.decrypt_block(ct))

