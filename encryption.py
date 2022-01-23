import hashlib
import json
import os
from base64 import b64encode, b64decode

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from werkzeug.security import generate_password_hash, check_password_hash


def encrypt_text(plaintext, password):
    data = bytes(plaintext, 'utf-8')
    password = bytes(password, 'utf-8')
    salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac('sha256', password, salt=salt, iterations=100000)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})
    hash_k = generate_password_hash(b64encode(key).decode('utf-8'), method='sha256', salt_length=16)
    return [result, hash_k, salt]


def check_password(encryption_key_hash, salt, password):
    password = bytes(password, 'utf-8')
    key = hashlib.pbkdf2_hmac('sha256', password, salt=salt, iterations=100000)
    return check_password_hash(encryption_key_hash, b64encode(key).decode('utf-8'))


def decrypt_text(cipher_dump, salt, password):
    password = bytes(password, 'utf-8')
    key = hashlib.pbkdf2_hmac('sha256', password, salt=salt, iterations=100000)
    try:
        b64 = json.loads(cipher_dump)
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except (ValueError, KeyError):
        return ""
