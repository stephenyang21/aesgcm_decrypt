import streamlit as st
import binascii

from decrypt import decrypt
from hex_json import hex_deserialize
#from cryptography.hazmat.primitives.ciphers.aead import AESGCM


st.title("AES-GCM  Decryption")

st.header("Decryption")
message = st.text_input("Enter the message to decrypt:")
key = st.text_input("Enter decryption key:")

okButtom = st.button("OK")

if okButtom:
    decrypted_message = decrypt(message.encode('utf-8'), (key.encode('utf-8')))
    data  =binascii.hexlify(decrypted_message).decode('utf-8')
    st.subheader("Decrypted Message" )
    st.write(data)
    st.subheader("JSON Message:")
    st.json(hex_deserialize(data))





