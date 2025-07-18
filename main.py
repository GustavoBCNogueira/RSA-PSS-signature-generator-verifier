import src.signature as signature
import src.key_generation as key_generation
import src.rsa as rsa
import src.utils as utils
from base64 import b64encode, b64decode
import math

op = 1
while op != 0:
    print("\n------------------------------------------------------------------------------------------------")
    print("\nDigite:")
    print("1 para realizar a geracao de chaves.")
    print("2 para realizar um encriptacao com RSA.")
    print("3 para realizar uma decriptacao com RSA.")
    print("4 para assinar um arquivo.")
    print("5 para verificar a assinatura de um arquivo.")
    print("0 para terminar a execucao do programa.")

    op = int(input())
    if op == 1:
        # gerando chaves, por meio da geracao de primos de n_bits bits
        n_bits = int(input("\nDigite o numero de bits de p e q para gerar as chaves (recomenda-se 2048 bits): "))
        keys = key_generation.generate_rsa_keys(n_bits+1)
        
        diff = input("\nDigite uma palavra para diferenciar estas chaves: ").split()[0]
        print()

        try:
            key_generation.write_public_pem("keys/public_key_" + diff + ".pem", keys['n'], keys['e'])
            key_generation.write_private_pem("keys/private_key_" + diff + ".pem", keys)

            print("\nChaves geradas e escritas em arquivos .pem com sucesso.")
        except:
            print("\nErro na escrita dos arquivos .pem")
    elif op == 2:
        pr_path = input("\nDigite o path relativo da chave privada a ser utilizada:\n").strip()

        try:
            n, d = key_generation.read_private_pem(pr_path)
        except FileNotFoundError:
            print("\nNao foi possivel abrir o arquivo .pem informado.\n")
            continue
        except ValueError:
            print("\nErro na interpretacao do arquivo pem.\n")
            continue

        n_bits = math.floor(math.log2(utils.bytes_to_int(n)))
        max_bytes = (n_bits-1) // 8

        msg = input("\nDigite a mensagem a ser criptografada, de no maximo " + str(max_bytes) + " caracteres:\n")
        if len(msg) > max_bytes:
            print("\nErro: Mensagem muito longa.\n")
            continue

        cipher = rsa.encrypt(msg.encode('utf-8'), d, n)
        print(cipher)
        print("\nMensagem criptografada em Base64:\n")
        print(b64encode(utils.int_to_bytes(cipher, n_bits // 8)).decode('utf-8'))
    elif op == 3:
        pu_path = input("\nDigite o path relativo da chave publica a ser utilizada:\n").strip()

        try:
            n, e = key_generation.read_public_pem(pu_path)
        except FileNotFoundError:
            print("\nNao foi possivel abrir o arquivo .pem informado.\n")
            continue
        except ValueError:
            print("\nErro na interpretacao do arquivo pem.\n")
            continue

        n_bits = math.floor(math.log2(utils.bytes_to_int(n)))
        num_bytes = n_bits // 8

        cipher = b64decode(input("\nDigite o texto cifrado a ser decifrado em Base64:\n").strip().encode('utf-8'))
        if len(cipher) != num_bytes:
            print("\nTamanho da mensagem nao condiz com o Mod da chave publica\n")
            continue
        plain = rsa.decrypt(utils.bytes_to_int(cipher), e, n, num_bytes)
        print("\nMensagem em claro:")
        print(plain.decode('utf-8'))
    elif op == 4:
        pass
    elif op == 5:
        pass
    print()
