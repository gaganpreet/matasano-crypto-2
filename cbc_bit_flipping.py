# 16. CBC bit flipping
# 
# Generate a random AES key.
# 
# Combine your padding code and CBC code to write two functions.
# 
# The first function should take an arbitrary input string, prepend the
# string:
#         "comment1=cooking%20MCs;userdata="
# and append the string:
#     ";comment2=%20like%20a%20pound%20of%20bacon"
# 
# The function should quote out the ";" and "=" characters.
# 
# The function should then pad out the input to the 16-byte AES block
# length and encrypt it under the random AES key.
# 
# The second function should decrypt the string and look for the
# characters ";admin=true;" (or, equivalently, decrypt, split the string
# on ;, convert each resulting string into 2-tuples, and look for the
# "admin" tuple. Return true or false based on whether the string exists.
# 
# If you've written the first function properly, it should not be
# possible to provide user input to it that will generate the string the
# second function is looking for.
# 
# Instead, modify the ciphertext (without knowledge of the AES key) to
# accomplish this.
# 
# You're relying on the fact that in CBC mode, a 1-bit error in a
# ciphertext block:
# 
# * Completely scrambles the block the error occurs in
# 
# * Produces the identical 1-bit error (/edit) in the next ciphertext
#  block.
# 
# Before you implement this attack, answer this question: why does CBC
# mode have this property?
'''
    
    ANSWER:

    Because CBC decode is

        decoded_block[i] = D(encoded_block[i], key) ^ encoded_block[i-1]

    It's completely independent of the decoded part of the previous block, only depends on the encoded part

    Are you even reading this? :)
'''

import urllib
import random
from base64 import b64decode
from string import printable
from util import blocks, string_xor
from implement_cbc import cbc_encrypt, cbc_decrypt
from detect_cipher import random_string, detect_cipher

class RandomAES():
    def __init__(self):
        self.key = random_string(16) 
        self.iv = '\0' * 16

    def encrypt(self, text):
        ''' Encrypt text with AES 128 CBC with a chosen random key
        '''
        prepend = 'comment1=cooking%20MCs;userdata='
        append = ';comment2=%20like%20a%20pound%20of%20bacon'

        return cbc_encrypt(prepend + urllib.quote(text) + append, self.key, self.iv)

    def decrypt(self, text):
        ''' Decrypt text with AES 128 CBC with a chosen random key
        '''
        return cbc_decrypt(text, self.key, self.iv)

def is_compromised(s):
    if s.find(';admin=true;') != -1:
        return True
    return False

def flip_bit(c, i):
    return chr(ord(c) ^ (1 << i))

def modify_bit_string(s, char_index, bit_index):
    ''' Flip the bit at bit_index in the character at char_index in s '''
    return s[:char_index] + flip_bit(s[char_index], bit_index) + s[char_index+1:]

if __name__ == '__main__':
    aes = RandomAES()
    to_insert = '3admin-true3' + '\0'*4

    # I did this part manually, but it should be easily automatable
    #
    # for i in xrange(255):
    #    if bitCount(i ^ ord(';')) == 1:
    #                print chr(i), repr(i)
    #
    # I picked up two characters with one differing bit from the output of the loop above
    #
    # bin(3) = 110011
    # bin(;) = 111011
    # (Differ on third bit)
    #
    # bin(-) = 101101
    # bin(=) = 111101
    # Differ on fourth bit

    encrypted = aes.encrypt(to_insert)
    print 'String is compromised: %s'%(is_compromised(aes.decrypt(encrypted)))

    print 'Modifying bits'
    # print blocks(encrypted, 16)
    encrypted = modify_bit_string(encrypted, 16, 3)
    encrypted = modify_bit_string(encrypted, 22, 4)
    encrypted = modify_bit_string(encrypted, 27, 3)
    # print blocks(encrypted, 16)


    decrypted = aes.decrypt(encrypted)

    print 'String is compromised: %s'%(is_compromised(decrypted))
