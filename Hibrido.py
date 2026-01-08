from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ---------- SERVIDOR ----------

class ServidorSeguro:
    def __init__(self):
        self.clave_privada = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.clave_publica = self.clave_privada.public_key()

    def descifrar_clave_sesion(self, clave_cifrada):
        return self.clave_privada.decrypt(
            clave_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

# ---------- CLIENTE ----------

class ClienteSeguro:
    def __init__(self, clave_publica_servidor):
        self.clave_sesion = Fernet.generate_key()
        self.cipher = Fernet(self.clave_sesion)
        self.clave_publica_servidor = clave_publica_servidor

    def cifrar_clave_sesion(self):
        return self.clave_publica_servidor.encrypt(
            self.clave_sesion,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def cifrar_mensaje(self, mensaje):
        return self.cipher.encrypt(mensaje.encode())

# ---------- SIMULACIÓN ----------

servidor = ServidorSeguro()
cliente = ClienteSeguro(servidor.clave_publica)

# Cliente envía clave de sesión cifrada
clave_sesion_cifrada = cliente.cifrar_clave_sesion()

# Servidor recupera clave de sesión
clave_sesion = servidor.descifrar_clave_sesion(clave_sesion_cifrada)

# Comunicación segura
cipher_servidor = Fernet(clave_sesion)

mensaje_cifrado = cliente.cifrar_mensaje("Transferencia bancaria: $5000")
mensaje_descifrado = cipher_servidor.decrypt(mensaje_cifrado)

print("Mensaje cifrado:", mensaje_cifrado)
print("Mensaje descifrado:", mensaje_descifrado.decode())