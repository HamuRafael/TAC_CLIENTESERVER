from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

# Cria diretório para armazenar chaves
os.makedirs('chaves', exist_ok=True)

# Gera chaves RSA (2048 bits)
chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Salva chave privada
with open("chaves/private.pem", "wb") as chave:
    chave.write(chave_privada.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

# Salva chave pública
with open("chaves/public.pem", "wb") as chave:
    chave.write(chave_privada.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Chaves RSA geradas com sucesso.")
