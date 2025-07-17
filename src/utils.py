from math import ceil
from hashlib import sha3_256
from base64 import b64encode
from textwrap import wrap

# globals
HASH_LEN = 32       # numero de bytes que o hash utilizado retorna
SALT_LEN = 32       # numero de bytes que sera utilizado no salt

# Função auxiliar de bases determinísticas de Miller-Rabin para garantir a correção
def _deterministic_bases(bits: int):
    if bits < 561: 
        return (2, 3, 5, 7, 11, 13, 17)

    return (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

def int_to_bytes(value: int, size: int) -> bytes:
    result = []
    orig = value
    while value > 0:
        result.append(value % 256)
        value //= 256

    if len(result) > size:
        raise ValueError("int_to_bytes: Integer " + str(orig) + " too big for bytes of size " + str(size) + ".")
    
    byte_seq = b""
    while size - len(byte_seq) > len(result):
        byte_seq += b"\x00"
    
    for b in result:
        byte_seq += bytes([b])

    return byte_seq

def hash(message: bytes) -> bytes:
    hasher = sha3_256()
    hasher.update(message)
    return hasher.digest()

def MGF1(mgfSeed: bytes, maskLen: int) -> bytes:
    global HASH_LEN

    mask = b""
    for cnt in range(ceil(maskLen / HASH_LEN)):
        mask += hash(mgfSeed + int_to_bytes(cnt, 4))

    return mask[:maskLen]

# Função auxiliar para codificação DER de comprimento
def _der_len(content: bytes) -> bytes:
    if len(content) < 0x80:
        return bytes([len(content)])
    length_bytes = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes

# Função auxiliar para codificação DER de INTEGER
def _der_int(val: int) -> bytes:
    if val == 0:
        raw = b"\x00"
    else:
        raw = val.to_bytes((val.bit_length() + 7) // 8, "big")
        if raw[0] & 0x80:                  
            raw = b"\x00" + raw
    return b"\x02" + _der_len(raw) + raw

# Função auxiliar para codificação DER de SEQUENCE
def _der_seq(*encoded_elements: bytes) -> bytes:
    body = b"".join(encoded_elements)
    return b"\x30" + _der_len(body) + body

# Função auxiliar para empacotar dados em formato PEM
def _pem_wrap(data: bytes, header: str, footer: str) -> str:
    b64 = b64encode(data).decode()
    lines = wrap(b64, 64)
    return f"-----BEGIN {header}-----\n" + "\n".join(lines) + \
           f"\n-----END {footer}-----\n"