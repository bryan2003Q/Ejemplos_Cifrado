from cryptography.fernet import Fernet

# 1. Generar una clave secreta (simétrica)
clave = Fernet.generate_key()
cipher = Fernet(clave)

# 2. Mensaje original
mensaje = "Este es un mensaje secreto".encode()

# 3. Cifrar el mensaje
mensaje_cifrado = cipher.encrypt(mensaje)

# 4. Descifrar el mensaje
mensaje_descifrado = cipher.decrypt(mensaje_cifrado)

print("Clave secreta:", clave)
print("Mensaje original:", mensaje.decode())
print("Mensaje cifrado:", mensaje_cifrado)
print("Mensaje descifrado:", mensaje_descifrado.decode())