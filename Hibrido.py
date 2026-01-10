import os
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Cargar clave pública
with open("clave_publica.pem", "rb") as f:
    clave_publica = load_pem_public_key(f.read())

# Generar clave AES
clave_aes = Fernet.generate_key()
fernet = Fernet(clave_aes)

archivo = input("Archivo académico a cifrar: ")

with open(archivo, "rb") as f:
    datos = f.read()

# Cifrar archivo con AES
archivo_cifrado = fernet.encrypt(datos)

# Cifrar clave AES con RSA
clave_aes_cifrada = clave_publica.encrypt(
    clave_aes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Guardar paquete híbrido
with open(archivo + ".secure", "wb") as f:
    f.write(len(clave_aes_cifrada).to_bytes(4, "big"))
    f.write(clave_aes_cifrada)
    f.write(archivo_cifrado)

print("[OK] Archivo cifrado con sistema híbrido")