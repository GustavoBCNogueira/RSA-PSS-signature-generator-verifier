import hashlib
import math
import utils

def hash(message: bytes) -> bytes:
    hasher = hashlib.sha3_256()
    hasher.update(message)
    return hasher.digest()

def MGF1(mgfSeed: bytes, maskLen: int) -> bytes:
    hashLen = 32    # numero de bytes que o hash utilizado retorna

    mask = b""
    for cnt in range(math.ceil(maskLen / hashLen)):
        mask += hash(mgfSeed + utils.int_to_bytes(cnt, 4))

    return mask[:maskLen]

