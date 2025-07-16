import hashlib

def hash(message: bytes) -> bytes:
    hasher = hashlib.sha3_256()
    hasher.update(message)
    return hasher.digest()