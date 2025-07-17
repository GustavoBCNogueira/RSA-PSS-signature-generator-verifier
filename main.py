import src.signature as signature
import src.key_generation as key_generation
import src.rsa as rsa
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
        # gerando chaves, por meio da geracao de primos de 2047 bits
        keys = key_generation.generate_rsa_keys(2048)
        
        diff = input("\nDigite uma palavra para diferenciar estas chaves: ").split()[0]
        print()

        try:
            key_generation.write_public_pem("keys/public_key_" + diff + ".pem", keys['n'], keys['e'])
            key_generation.write_private_pem("keys/private_key_" + diff + ".pem", keys)

            print("\nChaves geradas e escritas em arquivos .pem com sucesso.")
        except:
            print("\nErro na escrita dos arquivos .pem")
    elif op == 2:
        pass
    elif op == 3:
        pass
    elif op == 4:
        pass
    elif op == 5:
        pass
    print()
