import os
import io
import base64
from flask import (
    Flask, render_template, request,
    send_file, flash, redirect, url_for, session
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Almacenamiento temporal en memoria (educativo)
TEMP_STORAGE = {}

app = Flask(__name__)
app.secret_key = os.urandom(32)

# ==============================
# MODO EDUCATIVO
# ==============================
MODO_EDUCATIVO = True  # Cambiar a False en producción

# --------- CRIPTO LOGIC ---------

def derivar_clave(password: str, salt: bytes):
    """
    Deriva una clave AES (256 bits) desde una contraseña usando PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000
    )

    clave_bytes = kdf.derive(password.encode())
    clave_fernet = base64.urlsafe_b64encode(clave_bytes)

    clave_visible = clave_fernet.decode() if MODO_EDUCATIVO else None
    return clave_fernet, clave_visible


def cifrar_simetrico_stream(datos: bytes, password: str):
    salt = os.urandom(16)
    clave, clave_visible = derivar_clave(password, salt)

    fernet = Fernet(clave)
    datos_cifrados = fernet.encrypt(datos)

    buffer = io.BytesIO()
    buffer.write(salt)
    buffer.write(datos_cifrados)
    buffer.seek(0)

    return buffer, clave_visible, base64.b64encode(salt).decode()


def descifrar_simetrico_stream(datos: bytes, password: str):
    buffer = io.BytesIO(datos)

    salt = buffer.read(16)
    datos_cifrados = buffer.read()

    clave, clave_visible = derivar_clave(password, salt)
    fernet = Fernet(clave)

    datos_descifrados = fernet.decrypt(datos_cifrados)

    output = io.BytesIO(datos_descifrados)
    output.seek(0)

    return output, clave_visible, base64.b64encode(salt).decode()


# --------- ROUTES ---------

@app.route('/')
@app.route('/')
def index():
    session.pop('file_id', None)
    session.pop('file_id_desc', None)
    session.pop('clave_derivada', None)
    session.pop('salt', None)

    return render_template('index_simetrico.html')

@app.route('/cifrar', methods=['POST'])
def cifrar():
    archivo = request.files.get('archivo')
    password = request.form.get('password')

    if not archivo or not password:
        flash('Faltan datos para cifrar')
        return redirect(url_for('index'))

    try:
        resultado, clave_visible, salt_visible = cifrar_simetrico_stream(
            archivo.read(), password
        )

        file_id = os.urandom(8).hex()
        TEMP_STORAGE[file_id] = resultado.getvalue()

        session['file_id'] = file_id
        session['archivo_nombre'] = archivo.filename
        session['clave_derivada'] = clave_visible
        session['salt'] = salt_visible

        return redirect(url_for('resultado'))

    except Exception as e:
        flash(f'Error al cifrar: {str(e)}')
        return redirect(url_for('index'))


@app.route('/resultado')
def resultado():
    return render_template(
        'index_simetrico.html',
        clave_derivada=session.get('clave_derivada'),
        salt=session.get('salt'),
        listo_descargar=True
    )


@app.route('/descargar')
def descargar():
    file_id = session.get('file_id')
    data = TEMP_STORAGE.get(file_id)

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=session['archivo_nombre'] + ".enc",
        mimetype='application/octet-stream'
    )


@app.route('/descifrar', methods=['POST'])
def descifrar():
    archivo = request.files.get('archivo')
    password = request.form.get('password')

    if not archivo or not password:
        flash('Faltan datos para descifrar')
        return redirect(url_for('index'))

    try:
        resultado, clave_visible, salt_visible = descifrar_simetrico_stream(
            archivo.read(), password
        )

        file_id = os.urandom(8).hex()
        TEMP_STORAGE[file_id] = resultado.getvalue()

        session['file_id_desc'] = file_id
        session['archivo_nombre_desc'] = archivo.filename.replace('.enc', '')
        session['clave_derivada'] = clave_visible
        session['salt'] = salt_visible

        return redirect(url_for('resultado_descifrado'))

    except Exception:
        flash('Contraseña incorrecta o archivo corrupto')
        return redirect(url_for('index'))


@app.route('/resultado_descifrado')
def resultado_descifrado():
    return render_template(
        'index_simetrico.html',
        clave_derivada=session.get('clave_derivada'),
        salt=session.get('salt'),
        listo_descifrar=True
    )


@app.route('/descargar_descifrado')
def descargar_descifrado():
    file_id = session.get('file_id_desc')
    data = TEMP_STORAGE.get(file_id)

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=session['archivo_nombre_desc'],
        mimetype='application/octet-stream'
    )

if __name__ == '__main__':
    app.run(debug=True)