# Write an oracle function and use it to detect ECB.
# 
# Now that you have ECB and CBC working:
# 
# Write a function to generate a random AES key; that's just 16 random bytes.
# 
# Write a function that encrypts data under an unknown key --- that is,
# a function that generates a random key and encrypts under it.
# 
# The function should look like:
# 
# encryption_oracle(buffer)
#  => [MEANINGLESS JIBBER JABBER]
# 
# Under the hood, have the function APPEND 5-10 bytes (count chosen
# randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.
# 
# Now, have the function choose to encrypt under ECB 1/2 the time, and
# under CBC the other half (just use random IVs each time for CBC). Use
# rand(2) to decide which to use.
# 
# Now detect the block cipher mode the function is using each time. 

import sys
import random
from collections import Counter
import util
from cbc import cbc_encrypt

def random_string(length):
    ''' Generate a random string of length l'''
    return ''.join([chr(random.randint(0, 255)) for i in xrange(length)])

def encryption_oracle(text):
    # Append some random bytes both ways
    text = random_string(random.randint(5, 10)) + text + random_string(random.randint(5, 10))

    iv = random_string(16)
    key = random_string(16)

    if random.randint(0, 1):
        # ECB
        return util.ecb_encode(text, key) 
    else:
        # CBC
        return cbc_encrypt(text, key, iv)

def detect_cipher(encrypted):
    blocks = util.blocks(encrypted, 16)
    block_count = Counter()
    for block in blocks:
        block_count[block] += 1

    repeated = 0
    for k, v in block_count.items():
        if v > 1:
            repeated += v

    return "ECB" if repeated > 0 else "CBC"

if __name__ == '__main__':
    text = open('input').read()
    encrypted = encryption_oracle(text)

    print detect_cipher(encrypted)
