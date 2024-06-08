from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def build_kdf(salt: bytes) -> PBKDF2HMAC:
    kdf =  PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf

def derive(password: bytes, kdf: PBKDF2HMAC) -> bytes:
    key = kdf.derive(password)
    return key

def verify(password: bytes, key: bytes, kdf: PBKDF2HMAC) -> bool:
    return kdf.verify(password, key)

def build_cry(key: bytes) -> ChaCha20Poly1305:
    return ChaCha20Poly1305(key)

def encrypt(chacha: ChaCha20Poly1305, nonce: bytes, data: bytes, associated_data: bytes) -> bytes:
    ciphertext = chacha.encrypt(nonce=nonce, data=data, associated_data=associated_data)
    return ciphertext

def decrypt(chacha: ChaCha20Poly1305, nonce: bytes, data: bytes, associated_data: bytes) -> bytes:
    plaintext = chacha.decrypt(nonce=nonce, data=data, associated_data=associated_data)
    return plaintext