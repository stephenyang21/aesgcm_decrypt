
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt(encrypted_message, key):
    
    key = key.decode("utf-8")
    encrypted_message = encrypted_message.decode('utf-8')

    key = bytearray.fromhex(key)
    encrypted_message = bytearray.fromhex(encrypted_message)
    associated_data =  encrypted_message[:16]
    nonce = encrypted_message[16:28]
    ciphertext =  encrypted_message[28:]

    aesgcm = AESGCM(key) 

    plainText = aesgcm.decrypt(nonce, ciphertext,associated_data )

    return plainText

