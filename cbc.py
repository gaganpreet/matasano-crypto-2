# Implement CBC Mode
# 
# In CBC mode, each ciphertext block is added to the next plaintext
# block before the next call to the cipher core.
# 
# The first plaintext block, which has no associated previous ciphertext
# block, is added to a "fake 0th ciphertext block" called the IV.
# 
# Implement CBC mode by hand by taking the ECB function you just wrote,
# making it encrypt instead of decrypt (verify this by decrypting
# whatever you encrypt to test), and using your XOR function from
# previous exercise.
# 
# DO NOT CHEAT AND USE OPENSSL TO DO CBC MODE, EVEN TO VERIFY YOUR
# RESULTS. What's the point of even doing this stuff if you aren't going
# to learn from it?
# 
# The buffer at:
# 
#     https://gist.github.com/3132976
# 
# is intelligible (somewhat) when CBC decrypted against "YELLOW
# SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

import sys
import util
from base64 import b64decode
from pkcs_7_padding import pkcs_padding

def cbc_encrypt(text, key, iv):
    ''' CBC encrypt text with initialization vector iv and key '''
    block_length = len(iv)
    text = pkcs_padding(text, block_length)
    blocks = util.blocks(text, block_length)

    blocks[0] = util.string_xor(blocks[0], iv)
    blocks[0] = util.ecb_encode(blocks[0], key)

    for i in xrange(1, len(blocks)):
        blocks[i] = util.string_xor(blocks[i], blocks[i-1])
        blocks[i] = util.ecb_encode(blocks[i], key)

    return ''.join(blocks)

def cbc_decrypt(text, key, iv):
    ''' CBC decrypt text with initialization vector iv and key '''
    block_length = len(iv)
    blocks = util.blocks(text, block_length)

    decoded_blocks = [0] * len(blocks)

    decoded_blocks[0] = util.ecb_decode(blocks[0], key)
    decoded_blocks[0] = util.string_xor(decoded_blocks[0], iv)
    for i in xrange(1, len(blocks)):
        decoded_blocks[i] = util.ecb_decode(blocks[i], key)
        decoded_blocks[i] = util.string_xor(decoded_blocks[i], blocks[i-1])

    return ''.join(decoded_blocks)


if __name__ == '__main__':
    key = 'YELLOW SUBMARINE'
    iv = '\x00'*16

    # See if sys.argv has iv and key given
    if len(sys.argv) > 2:
        key = argv[1]
        if len(key) != 16:
            print 'Length of key is %d, but should be 16'%(len(key))
            sys.exit(0)

        iv = argv[2]
        if len(iv) != 16:
            print 'Length of IV is %d, but should be 16'%(len(iv))
            sys.exit(0)
    else:
        print '(Optional) Usage: %s key iv\n' %(sys.argv[0])

    # AES CBC encrypt
    text = open('cbc_input').read()
    print '''CBC encrypting cbc_input file with %s as key, and <%s> as iv (written to cbc_output)'''%(key, repr(iv))
    encrypted_text = cbc_encrypt(text, key, iv)

    with open('cbc_output', 'w') as f:
        f.write(encrypted_text)

    # AES CBC decrypt
    text = open('3132976/gistfile1.txt').read()
    text = b64decode(text)
    print '''CBC decrypting 3132976/gistfile1.txt with %s as key, and <%s> as iv (on stdout)'''%(key, repr(iv))
    print cbc_decrypt(text, key, iv)
