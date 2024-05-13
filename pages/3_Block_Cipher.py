import streamlit as st

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key."""
    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        xor_result = plaintext_byte ^ key_byte
        ciphertext.append(xor_result)
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key)  # XOR decryption is the same as encryption

def display_binary_representation(data, label):
    """Displays the binary representation of data along with characters."""
    st.write(f"{label}:", data)
    for byte in data:
        st.write(f"Binary: {format(byte, '08b')} | Character: {chr(byte)}")

st.title("XOR Cipher")

input_method = st.radio("Choose input method:", ("Text", "File"))

if input_method == "Text":
    plaintext = st.text_area("Enter Plain Text:")
    key = st.text_input("Enter Key:")
    
    if st.button("Encrypt/Decrypt"):
        if not plaintext or not key:
            st.write("Plaintext or key should not be empty.")
        else:
            plaintext_bytes = bytes(plaintext.encode())
            key_bytes = bytes(key.encode())
            
            encrypted_text = xor_encrypt(plaintext_bytes, key_bytes)
            decrypted_text = xor_decrypt(encrypted_text, key_bytes)
            
            st.subheader("Encryption Results:")
            display_binary_representation(plaintext_bytes, "Plaintext")
            display_binary_representation(key_bytes, "Key")
            st.info("Encrypted Ciphertext:", encrypted_text.decode())
    
            st.subheader("Decryption Results:")
            display_binary_representation(encrypted_text, "Ciphertext")
            display_binary_representation(key_bytes, "Key")
            st.info("Decrypted Plaintext:", decrypted_text.decode())


elif input_method == "File":
    file = st.file_uploader("Upload a file:")
    key = st.text_input("Enter Key:")
    
    if st.button("Encrypt/Decrypt"):
        if not file or not key:
            st.write("File or key should not be empty.")
        else:
            file_contents = file.read()
            key_bytes = bytes(key.encode())
            
            encrypted_file = xor_encrypt(file_contents, key_bytes)
            decrypted_file = xor_decrypt(encrypted_file, key_bytes)
            
            st.subheader("Encryption Results:")
            st.write("Encrypted File Size:", len(encrypted_file), "bytes")
            st.info("File has been encrypted successfully.")
            
            st.subheader("Decryption Results:")
            st.write("Decrypted File Size:", len(decrypted_file), "bytes")
            st.info("File has been decrypted successfully.")

            # Download decrypted file as a text file
            st.download_button(
                label="Download Decrypted File",
                data=decrypted_file,
                file_name="decrypted_file.txt",
                mime="text/plain"
            )
