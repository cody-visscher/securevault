import LocalCrypto as lc

def decrypt(filename, password):
    file = open(filename, 'rb')
    contents = file.read()
    salt = contents[0:16]
    nonce = contents[16:28]
    ciphertext = contents[28:]
    kdf = lc.build_kdf(salt)
    key = lc.derive(password, kdf)
    chacha = lc.build_cry(key)
    plaintext = lc.decrypt(chacha, nonce, ciphertext, salt)
    return plaintext
