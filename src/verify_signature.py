import math
import src.utils as utils
import src.rsa as rsa
from base64 import b64encode

# globals
HASH_LEN = utils.HASH_LEN       # numero de bytes que o hash utilizado retorna
SALT_LEN = utils.SALT_LEN       # numero de bytes que sera utilizado no salt

def EMSA_verify(orig_msg: bytes, encoded_msg: bytes, em_bits: int) -> bool:
    global HASH_LEN
    global SALT_LEN

    # Verificando se o tamanho do EM é válido
    em_len = math.ceil(em_bits / 8)
    if em_len < HASH_LEN + SALT_LEN + 2 or encoded_msg[-1] != 0xbc:
        return False
    
    msg_hash = utils.hash(orig_msg)
    
    # Recuperando a parte mascarada do db e o hash parcial da mensagem codificada
    masked_db = encoded_msg[:em_len - HASH_LEN - 1]
    hash_partial = encoded_msg[em_len - HASH_LEN - 1: em_len-1]

    # Verificando se os primeiros bits do db mascarado estão corretos
    byte_mask = 0
    for i in range(8 - (8 * em_len - em_bits)):
        byte_mask += 1 << i

    if masked_db[0] & byte_mask != masked_db[0]:
        return False
    
    # Gerando a máscara do db
    db_mask = utils.MGF1(hash_partial, em_len - HASH_LEN - 1)
    
    # Desmascarando o db
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    # Transformando os primeiros bits a esquerda do db para 0
    byte_mask = 0
    for i in range(8 - (8 * em_len - em_bits)):
        byte_mask += 1 << i
    
    db = utils.int_to_bytes(db[0] & byte_mask, 1) + db[1:]

    # Verificando se o db tem o formato correto de padding
    if db[:em_len - HASH_LEN - SALT_LEN - 2] != bytes(em_len - HASH_LEN - SALT_LEN - 2) or db[em_len - HASH_LEN - SALT_LEN - 2] != 0x01:
        return False
    
    # Recuperando o sal
    salt = db[em_len - HASH_LEN - SALT_LEN - 1:]

    # Verificando se o hash parcial da mensagem corresponde ao esperado
    message_partial = bytes([0] * 8) + msg_hash + salt
    msg_hash_partial = utils.hash(message_partial)

    if msg_hash_partial != hash_partial:
        return False
    return True

def verify(signature: bytes, orig_data: bytes, pu_e: bytes, pu_n: bytes) -> bool:
    # decifra a assinatura
    n_bits = math.floor(math.log2(utils.bytes_to_int(pu_n)))
    plain_sig = rsa.decrypt(utils.bytes_to_int(signature), pu_e, pu_n, math.ceil(n_bits / 8))
    signature = plain_sig[-(math.ceil((n_bits-1) / 8)):]
    return EMSA_verify(orig_data, signature, n_bits-1)
