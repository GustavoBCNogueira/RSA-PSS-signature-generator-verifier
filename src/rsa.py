import utils

def encrypt(plain: bytes, pr: bytes, n: bytes) -> int:
    plain = utils.bytes_to_int(plain)
    pr = utils.bytes_to_int(pr)
    n = utils.bytes_to_int(n)

    return utils.binpow(plain, pr, n)

def decrypt(cipher: int, pu: bytes, n: bytes, msg_len: int) -> bytes:
    pu = utils.bytes_to_int(pu)
    n = utils.bytes_to_int(n)

    return utils.int_to_bytes(utils.binpow(cipher, pu, n), msg_len)
