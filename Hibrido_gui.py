import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# --------- CRIPTO ---------

def cifrar_hibrido(archivo, clave_publica_path):
    with open(clave_publica_path, "rb") as f:
        clave_publica = load_pem_public_key(f.read())

    clave_aes = Fernet.generate_key()
    fernet = Fernet(clave_aes)

    with open(archivo, "rb") as f:
        datos = f.read()

    datos_cifrados = fernet.encrypt(datos)

    clave_aes_cifrada = clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(archivo + ".secure", "wb") as f:
        f.write(len(clave_aes_cifrada).to_bytes(4, "big"))
        f.write(clave_aes_cifrada)
        f.write(datos_cifrados)

def descifrar_hibrido(archivo, clave_privada_path):
    with open(clave_privada_path, "rb") as f:
        clave_privada = load_pem_private_key(f.read(), password=None)

    with open(archivo, "rb") as f:
        size = int.from_bytes(f.read(4), "big")
        clave_aes_cifrada = f.read(size)
        datos_cifrados = f.read()

    clave_aes = clave_privada.decrypt(
        clave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    fernet = Fernet(clave_aes)
    datos = fernet.decrypt(datos_cifrados)

    with open(archivo.replace(".secure", ""), "wb") as f:
        f.write(datos)

# --------- GUI ---------

def seleccionar_archivo(var):
    var.set(filedialog.askopenfilename())

def cifrar():
    cifrar_hibrido(archivo.get(), clave_publica.get())
    messagebox.showinfo("Éxito", "Archivo cifrado con sistema híbrido")

def descifrar():
    descifrar_hibrido(archivo.get(), clave_privada.get())
    messagebox.showinfo("Éxito", "Archivo descifrado correctamente")

app = tk.Tk()
app.title("Sistema Híbrido Académico")
app.geometry("480x300")

archivo = tk.StringVar()
clave_publica = tk.StringVar()
clave_privada = tk.StringVar()

tk.Label(app, text="Archivo académico").pack()
tk.Entry(app, textvariable=archivo, width=50).pack()
tk.Button(app, text="Seleccionar archivo", command=lambda: seleccionar_archivo(archivo)).pack(pady=5)

tk.Label(app, text="Clave pública (cifrar)").pack()
tk.Entry(app, textvariable=clave_publica, width=50).pack()
tk.Button(app, text="Seleccionar clave pública", command=lambda: seleccionar_archivo(clave_publica)).pack()

tk.Label(app, text="Clave privada (descifrar)").pack()
tk.Entry(app, textvariable=clave_privada, width=50).pack()
tk.Button(app, text="Seleccionar clave privada", command=lambda: seleccionar_archivo(clave_privada)).pack(pady=5)

tk.Button(app, text="CIFRAR ARCHIVO", command=cifrar, width=25).pack(pady=5)
tk.Button(app, text="DESCIFRAR ARCHIVO", command=descifrar, width=25).pack()

app.mainloop()