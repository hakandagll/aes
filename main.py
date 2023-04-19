from flask import Flask, render_template, request, send_file
from hashlib import md5
from Cryptodome.Cipher import AES
from os import urandom

app = Flask(__name__)

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = urandom(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write(salt)
    finished = False

    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        out_file.write(cipher.encrypt(chunk))

def decrypt(in_file, out_file, password, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        out_file.write(bytes(x for x in chunk))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    password = request.form['password']
    file = request.files['file']
    encrypted_file = 'encrypted_file'
    with open(encrypted_file, 'wb') as out_file:
        encrypt(file, out_file, password)
    return send_file(encrypted_file, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    password = request.form['password']
    file = request.files['file']
    decrypted_file = 'decrypted_file'
    with open(decrypted_file, 'wb') as out_file:
        decrypt(file, out_file, password)
    return send_file(decrypted_file, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)