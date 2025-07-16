import hashlib
import math
import secrets
import utils

# globals
HASH_LEN = 32       # numero de bytes que o hash utilizado retorna
SALT_LEN = 32       # numero de bytes que sera utilizado no salt

def hash(message: bytes) -> bytes:
    hasher = hashlib.sha3_256()
    hasher.update(message)
    return hasher.digest()

def MGF1(mgfSeed: bytes, maskLen: int) -> bytes:
    global HASH_LEN

    mask = b""
    for cnt in range(math.ceil(maskLen / HASH_LEN)):
        mask += hash(mgfSeed + utils.int_to_bytes(cnt, 4))

    return mask[:maskLen]

def EMSA_encode(message: bytes, max_len: int) -> bytes:    
    global HASH_LEN
    global SALT_LEN

    # verificando se temos bytes suficientes para criar essa codificacao
    em_len = math.ceil(max_len / 8)
    if em_len < HASH_LEN + SALT_LEN + 2:
        raise ValueError("Encoding Error, max_len too small.")
    
    # criando o salt e o hash do primeiro componente do EMSA
    salt = secrets.token_bytes(SALT_LEN)
    partial = bytes([0] * 8) + hash(message) + salt
    hash_partial = hash(partial)

    # criando o db
    ps = bytes([0] * (em_len - SALT_LEN - HASH_LEN - 2))
    db = ps + b'\x01' + salt
    db_mask = MGF1(hash_partial, em_len - HASH_LEN - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # setando os primeros 8*em_len - max_len bits como 0
    byte_mask = 0
    for i in range(8 - (8*em_len - max_len)):
        byte_mask += 1 << i
    fst_byte = masked_db[0]
    masked_db = utils.int_to_bytes(fst_byte & byte_mask, 1) + masked_db[1:]

    # retornando o EM final
    return masked_db + hash_partial + b'\xbc'
