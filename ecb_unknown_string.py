# Byte-at-a-time ECB decryption, Full control version
# 
# Copy your oracle function to a new function that encrypts buffers
# under ECB mode using a consistent but unknown key (for instance,
# assign a single random key, once, to a global variable).
# 
# Now take that same function and have it append to the plaintext,
# BEFORE ENCRYPTING, the following string:
# 
#   Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
#   aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
#   dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
#   YnkK
# 
# SPOILER ALERT: DO NOT DECODE THIS STRING NOW. DON'T DO IT.
# 
# Base64 decode the string before appending it. DO NOT BASE64 DECODE
# THE STRING BY HAND; MAKE YOUR CODE DO IT. The point is that you don't
# know its contents.
# 
# What you have now is a function that produces:
# 
#   AES-128-ECB(your-string || unknown-string, random-key)
# 
# You can decrypt "unknown-string" with repeated calls to the oracle
# function!
# 
# Here's roughly how:
# 
# a. Feed identical bytes of your-string to the function 1 at a time ---
# start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
# block size of the cipher. You know it, but do this step anyway.
# 
# b. Detect that the function is using ECB. You already know, but do
# this step anyways.
# 
# c. Knowing the block size, craft an input block that is exactly 1 byte
# short (for instance, if the block size is 8 bytes, make
# "AAAAAAA"). Think about what the oracle function is going to put in
# that last byte position.
# 
# d. Make a dictionary of every possible last byte by feeding different
# strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
# "AAAAAAAC", remembering the first block of each invocation.
# 
# e. Match the output of the one-byte-short input to one of the entries
# in your dictionary. You've now discovered the first byte of
# unknown-string.
# 
# f. Repeat for the next byte.

from base64 import b64decode
from string import printable
from util import ecb_encode
from detect_cipher import random_string, detect_cipher

unknown_string = '''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK'''

def random_aes(text):
    ''' Encrypt text with AES 128 ECB with a chosen random key
        Random key is chosen once per code invocation
    '''
    padding = b64decode(unknown_string)
    if 'key' not in random_aes.func_dict:
        random_aes.key = random_string(16) 
    key = random_aes.key

    return ecb_encode(text + padding, key)

def find_block_size():
    ''' Figure out the block size by continually increasing string length 
    '''
    substring = random_aes('a')
    length = 2
    while substring not in random_aes('a' * length):
        length += 1
    return length - 1

def build_dict(text, block_size):
    ''' Build a dictionary of all possible letters for lookup '''
    lookup_dict = {}
    for c in printable:
        e = random_aes(text + c)
        e = e[:block_size]
        lookup_dict[e] = c
    return lookup_dict

def decode(block_size):
    ''' Decode the string by introducing one character at a time  '''
    blocks = len(random_aes('')) / block_size

    # The whole string
    found = ''
    # String from the current block being decoded
    block_found = ''

    for current_block in xrange(blocks):
        # block_known length is always (block_size - 1)
        # This is hashed in lookup_dict, which gives one 
        # character from the unknown string at a time

        if len(block_found):
            block_known = block_found[1:]
        else:
            # For the first block
            block_known = 'a' * (block_size - 1)
        block_found = ''

        for l in xrange(block_size - 1, -1, -1):
            lookup_dict = build_dict(block_known, block_size)

            encrypted = random_aes('a' * l)
            encrypted_block = encrypted[block_size * current_block : block_size * (current_block + 1)]
            try:
                c = lookup_dict[encrypted_block]
            except KeyError:
                break

            # It's easier to understand this as byte shifting operations
            block_known = block_known[1:] + c
            block_found += c
        found += block_found
    return found

    
if __name__ == '__main__':
    # a
    block_size = find_block_size()

    # b
    cipher_mode = detect_cipher(random_aes(open('input').read()))
    print "Detected cipher mode %s\n\n"%(cipher_mode)

    if cipher_mode == 'ECB':
        # c
        decoded = decode(block_size)
        print decoded
