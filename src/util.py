#!/usr/bin/python

from Crypto.Cipher import AES
from base64 import b64decode

''' Some util functions '''

def blocks(text, block_size):
    ''' Divide a string into equal sized blocks '''
    return [text[start:start+block_size] for start in xrange(0, len(text), block_size)]

def string_xor(x, y):
    ''' Xor two equal length strings character by character '''
    return ''.join([chr(ord(a) ^ ord(b)) for a, b in zip(x, y)])

def ecb_decrypt(text, key):
    ''' Decode an AES-128 ECB cipher '''
    c = AES.new(key, AES.MODE_ECB)
    return c.decrypt(text)

def ecb_encrypt(text, key):
    ''' Encode an AES-128 ECB cipher '''
    text = pkcs_pad(text, len(key))
    c = AES.new(key, AES.MODE_ECB)
    return c.encrypt(text)

def pkcs_pad(string, block_size):
    ''' PKCS 7 pad a string '''
    pad_length = 0
    if len(string) % block_size > 0:
        pad_length = block_size - (len(string) % block_size)

    pad = chr(pad_length)
    return string + pad_length * pad
