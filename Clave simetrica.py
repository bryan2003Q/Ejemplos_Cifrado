import tkinter as tk
from tkinter import filedialog, messagebox
import os, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# --------- CRIPTO ---------

def generar_clave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def cifrar_archivo(ruta, password):
    salt = os.urandom(16)
    clave = generar_clave(password, salt)
    f = Fernet(clave)

    with open(ruta, "rb") as file:
        datos = file.read()

    with open(ruta + ".enc", "wb") as file:
        file.write(salt + f.encrypt(datos))

def descifrar_archivo(ruta, password):
    with open(ruta, "rb") as file:
        contenido = file.read()

    salt = contenido[:16]
    datos = contenido[16:]
    clave = generar_clave(password, salt)
    f = Fernet(clave)

    with open(ruta.replace(".enc", ""), "wb") as file:
        file.write(f.decrypt(datos))

# --------- GUI ---------

def seleccionar_archivo():
    ruta.set(filedialog.askopenfilename())

def cifrar():
    if not ruta.get() or not password.get():
        messagebox.showerror("Error", "Completa todos los campos")
        return
    cifrar_archivo(ruta.get(), password.get())
    messagebox.showinfo("Éxito", "Archivo cifrado correctamente")

def descifrar():
    if not ruta.get() or not password.get():
        messagebox.showerror("Error", "Completa todos los campos")
        return
    descifrar_archivo(ruta.get(), password.get())
    messagebox.showinfo("Éxito", "Archivo descifrado correctamente")

app = tk.Tk()
app.title("Seguridad Académica - Cifrado Simétrico")
app.geometry("420x230")

ruta = tk.StringVar()
password = tk.StringVar()

tk.Label(app, text="Archivo académico:").pack(pady=5)
tk.Entry(app, textvariable=ruta, width=45).pack()
tk.Button(app, text="Seleccionar archivo", command=seleccionar_archivo).pack(pady=5)

tk.Label(app, text="Contraseña:").pack()
tk.Entry(app, textvariable=password, show="*").pack(pady=5)

tk.Button(app, text="CIFRAR", command=cifrar, width=20).pack(pady=5)
tk.Button(app, text="DESCIFRAR", command=descifrar, width=20).pack()

app.mainloop()