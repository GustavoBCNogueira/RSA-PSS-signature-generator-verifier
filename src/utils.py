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

def bytes_to_int(msg: bytes) -> int:
    value = 0
    exp = len(msg)-1
    for b in msg:
        value += b * pow(256, exp)
        exp -= 1

    return value
