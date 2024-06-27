import hashlib

password = "password".encode()
salt = b'DgwTMe6jryEfASOa'

hash = hashlib.pbkdf2_hmac('sha256', password, salt, 600000)

print(f"Result: pbkdf2:sha256:600000${salt.decode('utf-8')}${hash.hex()}")