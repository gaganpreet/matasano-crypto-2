#!/usr/bin/python

from Crypto.Cipher import AES
from base64 import b64decode

''' Some util functions '''

def blocks(text, block_size):
    ''' Divide a string into equal sized blocks '''
    return [text[start:start+block_size] for start in xrange(0, len(text), block_size)]

def string_xor(x, y):
    ''' Xor two equal length strings character by character '''
    return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(x,y)])

def decode_aes_ecb(text, key):
    ''' Decode an AES-128 ECB cipher '''
    c = AES.new(key, AES.MODE_ECB)
    return c.decrypt(text)

def encode_aes_ecb(text, key):
    ''' Encode an AES-128 ECB cipher '''
    c = AES.new(key, AES.MODE_ECB)
    return c.encrypt(text)
