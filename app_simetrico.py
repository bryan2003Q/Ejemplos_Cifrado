import os
import io
import base64
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --------- CRIPTO LOGIC ---------

def derivar_clave(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave AES segura desde una contraseña
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def cifrar_simetrico_stream(datos_archivo: bytes, password: str) -> io.BytesIO:
    salt = os.urandom(16)
    clave = derivar_clave(password, salt)
    fernet = Fernet(clave)

    datos_cifrados = fernet.encrypt(datos_archivo)

    output = io.BytesIO()
    output.write(salt)               # 16 bytes de salt
    output.write(datos_cifrados)     # datos cifrados
    output.seek(0)
    return output

def descifrar_simetrico_stream(datos_archivo: bytes, password: str) -> io.BytesIO:
    input_stream = io.BytesIO(datos_archivo)

    salt = input_stream.read(16)
    datos_cifrados = input_stream.read()

    clave = derivar_clave(password, salt)
    fernet = Fernet(clave)

    datos = fernet.decrypt(datos_cifrados)

    output = io.BytesIO(datos)
    output.seek(0)
    return output

# --------- ROUTES ---------

@app.route('/')
def index():
    return render_template('index_simetrico.html')

@app.route('/cifrar', methods=['POST'])
def cifrar():
    if 'archivo' not in request.files or 'password' not in request.form:
        flash('Faltan datos para cifrar')
        return redirect(url_for('index'))

    archivo = request.files['archivo']
    password = request.form['password']

    if archivo.filename == '' or password.strip() == '':
        flash('Debe seleccionar un archivo y escribir una contraseña')
        return redirect(url_for('index'))

    try:
        resultado = cifrar_simetrico_stream(archivo.read(), password)
        return send_file(
            resultado,
            as_attachment=True,
            download_name=archivo.filename + ".enc",
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash(f'Error al cifrar: {str(e)}')
        return redirect(url_for('index'))

@app.route('/descifrar', methods=['POST'])
def descifrar():
    if 'archivo' not in request.files or 'password' not in request.form:
        flash('Faltan datos para descifrar')
        return redirect(url_for('index'))

    archivo = request.files['archivo']
    password = request.form['password']

    if archivo.filename == '' or password.strip() == '':
        flash('Debe seleccionar un archivo y escribir la contraseña')
        return redirect(url_for('index'))

    try:
        resultado = descifrar_simetrico_stream(archivo.read(), password)
        return send_file(
            resultado,
            as_attachment=True,
            download_name=archivo.filename.replace(".enc", ""),
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash(f'Error al descifrar (contraseña incorrecta o archivo corrupto)')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)