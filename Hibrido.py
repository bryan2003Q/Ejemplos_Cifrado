from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# 1. Receptor genera claves RSA
clave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
clave_publica = clave_privada.public_key()

# 2. Emisor genera clave simétrica (AES)
clave_simetrica = Fernet.generate_key()
cipher_aes = Fernet(clave_simetrica)

# 3. Emisor cifra la clave simétrica con la clave pública RSA
clave_simetrica_cifrada = clave_publica.encrypt(
    clave_simetrica,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 4. Emisor cifra el mensaje con AES
mensaje = "Mensaje ultra secreto usando sistema híbrido".encode()
mensaje_cifrado = cipher_aes.encrypt(mensaje)

# 5. Receptor descifra la clave simétrica
clave_simetrica_descifrada = clave_privada.decrypt(
    clave_simetrica_cifrada,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 6. Receptor descifra el mensaje
cipher_descifrado = Fernet(clave_simetrica_descifrada)
mensaje_descifrado = cipher_descifrado.decrypt(mensaje_cifrado)

print("Mensaje original:", mensaje.decode())
print("Mensaje cifrado:", mensaje_cifrado)
print("Mensaje descifrado:", mensaje_descifrado.decode())