# 14. Byte-at-a-time ECB decryption, Partial control version
# 
# Take your oracle function from #12. Now generate a random count of
# random bytes and prepend this string to every plaintext. You are now
# doing:
# 
#   AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
# 
# Same goal: decrypt the target-bytes.
# 
# What's harder about doing this?
# 
# How would you overcome that obstacle? The hint is: you're using
# all the tools you already have; no crazy math is required.
# 
# Think about the words "STIMULUS" and "RESPONSE".

import random
import math
from base64 import b64decode
from string import printable
from util import ecb_encrypt, blocks
from detect_cipher import random_string

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
        random_aes.prefix = random_string(random.randint(0, 100)) 
    key = random_aes.key
    prefix = random_aes.prefix

    return ecb_encrypt(prefix + text + padding, key) 

def build_dict(text, block_size, prefix_padding, skip_blocks):
    ''' Build a dictionary of all possible letters for lookup '''
    lookup_dict = {}
    for c in printable:
        e = random_aes(prefix_padding * 'a' + text + c)
        e = e[(block_size * skip_blocks):(block_size * (skip_blocks + 1))]
        lookup_dict[e] = c
    return lookup_dict

def is_repeated(l):
    ''' Check if a list has any two consecutive elements repeated '''
    for i in xrange(1, len(l)):
        if l[i] == l[i-1]:
            return i
    return False

def find_prefix_length(block_size):
    ''' Finds the prefix length of random_aes.
        Starts off with a string of length block_size * 2, and increases
        it till there are two repeated blocks in the encrypted text
    '''
    s = 'a' * block_size * 2
    
    while True:
        encrypted_text = random_aes(s)
        encrypted_blocks = blocks(encrypted_text, block_size)

        first_repetition = is_repeated(encrypted_blocks)
        if first_repetition is not False:
            return (first_repetition + 1) * block_size - len(s)

        s += 'a'

def decode(block_size):
    ''' Decode the string by introducing one character at a time  '''
    prefix_length = find_prefix_length(block_size)
    print 'Detected prefix of length %d' % (prefix_length)

    skip_blocks = int(math.ceil(1.0 * prefix_length/block_size))
    prefix_padding = block_size - prefix_length % block_size

    blocks = len(random_aes('a' * prefix_padding)) / block_size

    print '''Blocks to skip: %d
Padding to add: %d\n\n\n''' % (skip_blocks, prefix_padding)
    # The whole string
    found = ''
    # String from the current block being decoded
    block_found = ''

    for current_block in xrange(blocks - skip_blocks):
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
            lookup_dict = build_dict(block_known, block_size, prefix_padding, skip_blocks)

            encrypted = random_aes('a' * prefix_padding + 'a' * l)
            encrypted_block = encrypted[block_size * (current_block + skip_blocks):
                                        block_size * (skip_blocks + current_block + 1)]
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
    block_size = 16

    decoded = decode(block_size)
    print decoded
