import hashlib
import math
import secrets
import src.utils as utils
import src.rsa as rsa
from base64 import b64encode

# globals
HASH_LEN = utils.HASH_LEN       # numero de bytes que o hash utilizado retorna
SALT_LEN = utils.SALT_LEN       # numero de bytes que sera utilizado no salt

def EMSA_encode(message: bytes, max_len: int) -> bytes:    
    global HASH_LEN
    global SALT_LEN

    # verificando se temos bytes suficientes para criar essa codificacao
    em_len = math.ceil(max_len / 8)
    if em_len < HASH_LEN + SALT_LEN + 2:
        raise ValueError("Encoding Error, max_len too small.")
    
    # criando o salt e o hash do primeiro componente do EMSA
    salt = secrets.token_bytes(SALT_LEN)
    partial = bytes([0] * 8) + utils.hash(message) + salt
    hash_partial = utils.hash(partial)

    # criando o db
    ps = bytes([0] * (em_len - SALT_LEN - HASH_LEN - 2))
    db = ps + b'\x01' + salt
    db_mask = utils.MGF1(hash_partial, em_len - HASH_LEN - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    # setando os primeros 8*em_len - max_len bits como 0
    byte_mask = 0
    for i in range(8 - (8*em_len - max_len)):
        byte_mask += 1 << i
    fst_byte = masked_db[0]
    masked_db = utils.int_to_bytes(fst_byte & byte_mask, 1) + masked_db[1:]

    # retornando o EM final
    return masked_db + hash_partial + b'\xbc'

def sign(message: bytes, pr: bytes, n: bytes) -> bytes:
    num_bits = math.floor(math.log2(utils.bytes_to_int(n)))
    padded_msg = EMSA_encode(message, num_bits - 1)
    return b64encode(utils.int_to_bytes(rsa.encrypt(padded_msg, pr, n), math.ceil(num_bits / 8)))
