import secrets
import math
import src.utils as utils
import base64
import re

# Gerando os primeiros 500 primos para otimizar a verificação de primalidade
FIRST_500_PRIMES = [
     2,    3,    5,    7,   11,   13,   17,   19,   23,   29,
    31,   37,   41,   43,   47,   53,   59,   61,   67,   71,
    73,   79,   83,   89,   97,  101,  103,  107,  109,  113,
   127,  131,  137,  139,  149,  151,  157,  163,  167,  173,
   179,  181,  191,  193,  197,  199,  211,  223,  227,  229,
   233,  239,  241,  251,  257,  263,  269,  271,  277,  281,
   283,  293,  307,  311,  313,  317,  331,  337,  347,  349,
   353,  359,  367,  373,  379,  383,  389,  397,  401,  409,
   419,  421,  431,  433,  439,  443,  449,  457,  461,  463,
   467,  479,  487,  491,  499,  503,  509,  521,  523,  541,
   547,  557,  563,  569,  571,  577,  587,  593,  599,  601,
   607,  613,  617,  619,  631,  641,  643,  647,  653,  659,
   661,  673,  677,  683,  691,  701,  709,  719,  727,  733,
   739,  743,  751,  757,  761,  769,  773,  787,  797,  809,
   811,  821,  823,  827,  829,  839,  853,  857,  859,  863,
   877,  881,  883,  887,  907,  911,  919,  929,  937,  941,
   947,  953,  967,  971,  977,  983,  991,  997, 1009, 1013,
  1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
  1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151,
  1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
  1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
  1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373,
  1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
  1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
  1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583,
  1587, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637,
  1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723,
  1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801,
  1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879,
  1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979,
  1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039,
  2053, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
  2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213,
  2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287,
  2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
  2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
  2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531,
  2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617,
  2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687,
  2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,
  2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
  2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903,
  2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999,
  3001, 3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
  3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167, 3169, 3181,
  3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257,
  3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
  3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
  3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511,
  3517, 3527, 3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571
]

# Função de Miller-Rabin para verificar a primalidade
def _miller_rabin(n: int, bases) -> bool:
    r, d = 0, n - 1
    while d % 2 == 0:
        r, d = r + 1, d >> 1

    for a in bases:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False       # composite
    return True                # probably prime


# Função para verificar se um número é primo, 
# usando uma combinação de divisão por pequenos primos e o teste de Miller-Rabin
def is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    # small‑prime trial division
    for p in FIRST_500_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    # Miller–Rabin
    bases = utils._deterministic_bases(n.bit_length())
    return _miller_rabin(n, bases)

# Função para gerar um primo randômico de tamanho exato em bits
def generate_prime(bits: int = 1024) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << bits - 1) | 1          # force MSB and odd
        if is_probable_prime(candidate):
            return candidate
        
# Algoritmo de inversão modular usando Euclides estendido
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0

# Função para geração de par de chaves RSA
def generate_rsa_keys(bits=1024):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)

    n   = p * q
    phi = (p - 1) * (q - 1)
    e   = 65537 if math.gcd(65537, phi) == 1 else 3
    d   = modinv(e, phi)
    dP  = d % (p - 1)
    dQ  = d % (q - 1)
    qInv = modinv(q, p)

    return {
        "n": n, "e": e, "d": d,
        "p": p, "q": q,
        "dP": dP, "dQ": dQ, "qInv": qInv,
    }

# Função para escrever chave pública em formato PEM
def write_public_pem(filename: str, n: int, e: int):
    der = utils._der_seq(utils._der_int(n), utils._der_int(e))
    pem = utils._pem_wrap(der, "RSA PUBLIC KEY", "RSA PUBLIC KEY")
    with open(filename, "w", encoding="utf‑8") as f:
        f.write(pem)

# Função para escrever chave privada em formato PEM
def write_private_pem(filename: str, params: dict):
    der = utils._der_seq(
        utils._der_int(0),                      
        utils._der_int(params["n"]),
        utils._der_int(params["e"]),
        utils._der_int(params["d"]),
        utils._der_int(params["p"]),
        utils._der_int(params["q"]),
        utils._der_int(params["dP"]),
        utils._der_int(params["dQ"]),
        utils._der_int(params["qInv"]),
    )
    pem = utils._pem_wrap(der, "RSA PRIVATE KEY", "RSA PRIVATE KEY")
    with open(filename, "w", encoding="utf‑8") as f:
        f.write(pem)

# Função para ler chave pública em formato PEM
def read_public_pem(filename: str):
    # Abrindo o arquivo PEM
    with open(filename, "r", encoding="utf-8") as f:
        pem = f.read()

    # Verificando se o formato PEM é válido
    match = re.search(r"-----BEGIN RSA PUBLIC KEY-----(.*?)-----END RSA PUBLIC KEY-----", pem, re.DOTALL)
    if not match:
        raise ValueError("Invalid public key PEM format")

    # Decodificando o conteúdo DER
    der = base64.b64decode(match.group(1).replace("\n", "").replace("\r", ""))

    # Verificando se o DER começa com SEQUENCE
    offset = 0
    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE")
    
    # Lendo o comprimento do SEQUENCE
    _, offset = utils._read_asn1_len(der, offset + 1)

    # Lendo os componentes n e e
    n_bytes, offset = utils._read_asn1_int(der, offset)
    e_bytes, offset = utils._read_asn1_int(der, offset)

    # retorna os bytes de n e e
    return n_bytes, e_bytes

def read_private_pem(filename: str):
    # Abrindo o arquivo PEM
    with open(filename, "r", encoding="utf-8") as f:
        pem = f.read()

    # Verificando se o formato PEM é válido
    match = re.search(r"-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----", pem, re.DOTALL)
    if not match:
        raise ValueError("Invalid private key PEM format")

    # Decodificando o conteúdo DER
    der = base64.b64decode(match.group(1).replace("\n", "").replace("\r", ""))

    # Verificando se o DER começa com SEQUENCE
    offset = 0
    if der[offset] != 0x30:
        raise ValueError("Expected SEQUENCE")
    _, offset = utils._read_asn1_len(der, offset + 1)

    # Lendo a versão da chave privada
    version_bytes, offset = utils._read_asn1_int(der, offset)
    version = int.from_bytes(version_bytes, "big")
    if version != 0:
        raise ValueError("Unsupported RSA key version")

    # Lendo os componentes n, e, e d da chave privada
    keys = {}
    keys["n"], offset = utils._read_asn1_int(der, offset)
    keys["e"], offset = utils._read_asn1_int(der, offset)
    keys["d"], offset = utils._read_asn1_int(der, offset)

    # Retornando os componentes n e d da chave privada
    return keys["n"], keys["d"]

# Função principal para gerar, salvar e ler chaves RSA
if __name__ == "__main__":
    key_bits = 1024
    print(f"[+] Gerando par de chaves de {key_bits*2} bits  …")
    kp = generate_rsa_keys(key_bits)

    write_public_pem("public_key.pem",  kp["n"], kp["e"])
    write_private_pem("private_key.pem", kp)

    print("[✓] public_key.pem e private_key.pem gerados com sucesso.")

    n_public, e = read_public_pem("public_key.pem")
    n_private, d = read_private_pem("private_key.pem")