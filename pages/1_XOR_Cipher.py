import streamlit as st

st.title("XOR Cipher")

plaintext = st.text_area("Plain Text:")
plaintext = bytes(plaintext.encode())

key = st.text_input("Key:")
key = bytes(key.encode())

if st.button("Submit"):
    st.write("")
    st.subheader("Output:")
    st.write("")
    if not plaintext or not key:
        st.write("Plaintext or key should not be empty.")
    else:
        def xor_encrypt(plaintext, key):
            """Encrypts plaintext using XOR cipher with the given key, st.writeing bits involved."""
            ciphertext = bytearray()
            for i in range(len(plaintext)):
                plaintext_byte = plaintext[i]
                key_byte = key[i % len(key)]
                xor_result = plaintext_byte ^ key_byte
                ciphertext.append(xor_result)

                st.write(f"Plaintext byte: {format(plaintext_byte, '08b')} = {chr(plaintext_byte)}")
                st.write(f"Key byte:       {format(key_byte, '08b')} = {chr(key_byte)}")
                st.write(f"XOR result:     {format(xor_result, '08b')} = {chr(xor_result)}")
                st.write("-"*20)
                
            return ciphertext

        def xor_decrypt(ciphertext, key):
            """Decrypts ciphertext using XOR cipher with the given key."""
            return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption

        if plaintext.decode() == key.decode():
            st.write("Plaintext should not be equal to the key")
        elif len(plaintext.decode()) < len(key.decode()):
            st.write("Plaintext length should be equal or greater than the length of key")
        else:
            encrypted_text = xor_encrypt(plaintext, key)
            st.write("Ciphertext:", encrypted_text.decode())
            decrypted_text = xor_decrypt(encrypted_text, key)
            st.write("Decrypted:", decrypted_text.decode())





