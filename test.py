from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

SECRET_KEY="*F-JaNdRfUjXn2r5u8x/A?D(G+KbPeSh"
SALT="ThWmZq3t6w9z$C&F)J@NcRfUjXn2r5u7"

def encrypt_password(password):
    key = PBKDF2(SECRET_KEY, SALT)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    (ciphertext, tag) = cipher.encrypt_and_digest(password.encode())
    return (ciphertext, tag, nonce)

def decrypt_password(ciphertext, tag, nonce):
    key = PBKDF2(SECRET_KEY, SALT)
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    password = cipher.decrypt(ciphertext)
    return password.decode()

(a, b, c) = encrypt_password("siema")
print(type(a))

print(decrypt_password(a, b, c))