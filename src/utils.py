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
    
    result.reverse()
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



# Função auxiliar para ler o comprimento ASN.1
def _read_asn1_len(data: bytes, offset: int):
    # Extrai o primeiro byte
    first = data[offset]

    # Se o primeiro byte for menor que 0x80, é o comprimento direto
    offset += 1
    if first < 0x80:
        return first, offset
    
    # Se o primeiro byte for 0x80 ou maior, indica o número de bytes que seguem
    num_bytes = first & 0x7F

    # O comprimento é lido a partir dos próximos bytes e retorna o valor e o novo offset
    val = int.from_bytes(data[offset:offset + num_bytes], byteorder="big")
    return val, offset + num_bytes

# Função auxiliar para ler um INTEGER ASN.1
def _read_asn1_int(data: bytes, offset: int):
    # Verifica se o primeiro byte é do tipo INTEGER
    if data[offset] != 0x02:
        raise ValueError("Expected INTEGER")
    
    # Incrementa o offset para o próximo byte
    offset += 1
    
    # Lê o comprimento do INTEGER e altera o offset
    length, offset = _read_asn1_len(data, offset)

    # O valor INTEGER é lido a partir do offset atual e retorna o valor e o novo offset
    val_bytes = data[offset:offset + length]
    return val_bytes, offset + length

def bytes_to_int(msg: bytes) -> int:
    value = 0
    exp = len(msg)-1
    for b in msg:
        value += b * pow(256, exp)
        exp -= 1

    return value

# exponenciacao rapida, complexidade O(log2(exp)), considerando que a multiplicacao ocorre em O(1)
def binpow(base: int, exp: int, mod: int) -> int:
    res = 1

    while exp > 0:
        if exp%2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    
    return res
