'''
Implement PKCS#7 padding

Pad any block to a specific block length, by appending the number of
bytes of padding to the end of the block. For instance,

  "YELLOW SUBMARINE"

padded to 20 bytes would be:

  "YELLOW SUBMARINE\x04\x04\x04\x04"

The particulars of this algorithm are easy to find online.
'''

import sys

def pkcs_padding(string, block_size):
    ''' PKCS 7 pad a string '''
    pad_length = 0
    if len(string) % block_size > 0:
        pad_length = block_size - (len(string) % block_size)
    
    pad = chr(pad_length)
    return string + pad_length * pad

if __name__ == '__main__':
    if len(sys.argv) == 3:
        string = sys.argv[1]
        block_size = sys.argv[2]
    else:
        print '(Optional) Usage: %s "YELLOW SUBMARINE" 8\n'%(sys.argv[0])
        block_size = 20
        string = 'YELLOW SUBMARINE'

    print '''PKCS#7 padded string: %s
For:
String: %s
Block size: %s'''%(repr(pkcs_padding(string, int(block_size))), string, block_size)
