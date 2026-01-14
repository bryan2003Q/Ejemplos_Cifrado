from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generar claves RSA
clave_privada = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

clave_publica = clave_privada.public_key()

# Guardar clave privada
with open("clave_privada.pem", "wb") as f:
    f.write(
        clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Guardar clave pública
with open("clave_publica.pem", "wb") as f:
    f.write(
        clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("[OK] Claves RSA generadas")