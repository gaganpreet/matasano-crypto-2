# ECB cut-and-paste
# 
# Write a k=v parsing routine, as if for a structured cookie. The
# routine should take:
# 
#    foo=bar&baz=qux&zap=zazzle
# 
# and produce:
# 
#   {
#     foo: 'bar',
#     baz: 'qux',
#     zap: 'zazzle'
#   }
# 
# (you know, the object; I don't care if you convert it to JSON).
# 
# Now write a function that encodes a user profile in that format, given
# an email address. You should have something like:
# 
#   profile_for("foo@bar.com")
# 
# and it should produce:
# 
#   {
#     email: 'foo@bar.com',
#     uid: 10,
#     role: 'user'
#   }
# 
# encoded as:
# 
#   email=foo@bar.com&uid=10&role=user
# 
# Your "profile_for" function should NOT allow encoding metacharacters
# (& and =). Eat them, quote them, whatever you want to do, but don't
# let people set their email address to "foo@bar.com&role=admin".
# 
# Now, two more easy functions. Generate a random AES key, then:
# 
#  (a) Encrypt the encoded user profile under the key; "provide" that
#  to the "attacker".
# 
#  (b) Decrypt the encoded user profile and parse it.
# 
# Using only the user input to profile_for() (as an oracle to generate
# "valid" ciphertexts) and the ciphertexts themselves, make a role=admin
# profile.

from detect_cipher import random_string
from util import ecb_decode, ecb_encode, blocks

def kv_parser(s):
    o = {}
    for pair in s.split('&'):
        try:
            k, v = pair.split('=')
        except:
            k = pair.split('=')[0]
            v = ''
        o[k] = v
    return o

class Profile:
    def __init__(self):
        self.key = random_string(16)

    def profile_for(self, email):
        email = email.replace('&', '%26').replace('=', '%3d')
        return 'email=%s&uid=10&role=user'%(email)

    def encrypt(self, email):
        ''' Encrypt user profile with AES 128 ECB with a chosen random key
            Random key is chosen once per code invocation
        '''
        key = self.key
        return ecb_encode(self.profile_for(email), self.key)

    def decrypt(self, text):
        ''' Decrypt user profile with AES 128 ECB with a chosen random key
            Random key is chosen once per code invocation
        '''
        key = self.key
        decrypted = ecb_decode(text, self.key)
        o = kv_parser(decrypted)
        print 'Welcome ' + o['email'] + '. Your role is: ', o['role']

profile = Profile()

def first_repeated(l):
    for i in xrange(1, len(l)):
        if l[i] == l[i-1]:
            return i
    return False

def find_prefix_length(block_size):
    ''' Finds the prefix length 
        Starts off with a string of length block_size * 2, and increases
        it till there are two repeated blocks in the encrypted text
    '''
    s = 'a' * block_size * 2
    
    while True:
        encrypted_text = profile.encrypt(s)                                                                                                                                                                                                                                         
        encrypted_blocks = blocks(encrypted_text, block_size)

        first_repetition = first_repeated(encrypted_blocks)
        if first_repetition is not False:
            return (first_repetition + 1) * block_size - len(s)

        s += 'a'

if __name__ == '__main__':
    block_size = 16
    prefix_length = find_prefix_length(block_size)
    suffix_length = 17 # Not computing it here, but can be found similarly to prefix length computation

    profile.decrypt(profile.encrypt('foo@bar.com'))

    # First create an encrypted block so that admin is at the start of the block
    # It should be like this
    # |________________| |_____________| |admin______| |____________|
    padding_length = block_size - prefix_length % block_size
    email = 'a' * padding_length + 'admin'

    encrypted = profile.encrypt(email)

    block_to_copy = blocks(encrypted, 16)[prefix_length/block_size + 1]


    # Now we need to get so that role=user is divided on the =
    # 'role=' is at the right boundary of a block, and 'admin'
    # is at the left boundary of the next block, which we'll overwrite
    # It should be like this
    # |________________| |_________role=| |user______|
    cruft_length = prefix_length + (suffix_length - 4)
    
    # Number of bytes required to round cruft to nearest block_size
    padding_length = block_size - cruft_length % block_size

    encrypted = profile.encrypt('a' * padding_length)

    encrypted_blocks = blocks(encrypted, block_size)
    encrypted_blocks[-1] = block_to_copy

    profile.decrypt(''.join(encrypted_blocks))
