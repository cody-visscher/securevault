import LocalCrypto as lc
import os

def encrypt(filename, password):
    salt = os.urandom(16)
    kdf = lc.build_kdf(salt)
    key = lc.derive(password, kdf)
    nonce = os.urandom(12)
    file = open(filename, 'rb')
    plaintext = file.read()
    chacha = lc.build_cry(key)
    ciphertext = lc.encrypt(chacha, nonce, plaintext, salt)
    contents = salt+nonce+ciphertext
    return contents