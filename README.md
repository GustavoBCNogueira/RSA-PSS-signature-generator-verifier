# 🔐 RSA-PSS Signature Generator & Verifier

Este projeto oferece uma interface interativa para geração de chaves RSA, encriptação, decriptação, assinatura digital e verificação de assinaturas utilizando RSA-PSS.

## ▶️ Como executar

Certifique-se de que você tenha o Python 3 instalado.

No terminal, execute:

```bash
python3 main.py
```
Você verá o seguinte menu:
```
Digite:
1 para realizar a geracao de chaves.
2 para realizar um encriptacao com RSA.
3 para realizar uma decriptacao com RSA.
4 para assinar um arquivo.
5 para verificar a assinatura de um arquivo.
0 para terminar a execucao do programa.
```
## 🧭 Funcionalidades do Menu
### 1️⃣ Geração de chaves
- O usuário informa o tamanho em bits dos primos p e q (ex: 1024 ou 2048).
- Em seguida, informa um nome base para salvar os arquivos.
- As chaves são salvas em arquivos .pem dentro da pasta keys/.

### 2️⃣ Encriptação com RSA
- Informe o caminho da chave pública a ser usada (ex: keys/nome_public.pem).
- Digite a mensagem a ser encriptada.
- O programa exibirá o texto encriptado.

### 3️⃣ Decriptação com RSA
- Informe o caminho da chave privada (ex: keys/nome_private.pem).
- Digite a mensagem encriptada.
- O programa exibirá o texto original.

### 4️⃣ Assinatura de arquivo
- Informe o caminho relativo da chave privada e da chave pública.
- Informe o caminho do arquivo a ser assinado.
- Defina o nome do arquivo .sig que conterá a assinatura.

### 5️⃣ Verificação de assinatura
- Informe o caminho do arquivo .sig a ser verificado.
- O programa validará a assinatura com a chave pública.
