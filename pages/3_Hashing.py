import streamlit as st
import hashlib

def calculate_hash(data, hash_type):
    hasher = hashlib.new(hash_type)
    hasher.update(data)
    return hasher.hexdigest()

st.title("Hashing Functions")

option = st.radio("Choose input method:", ("Text", "File"))

if option == "Text":
    text = st.text_input("Enter text to hash:")
    if text:
        st.write("You entered:", text)

        st.subheader("Choose a hash function:")
        hash_md5 = st.checkbox("MD5")
        hash_sha1 = st.checkbox("SHA1")
        hash_sha256 = st.checkbox("SHA256")
        hash_sha512 = st.checkbox("SHA512")

        if hash_md5:
            hashed_text = calculate_hash(text.encode(), "md5")
            st.write("MD5 Hash:", hashed_text)
        if hash_sha1:
            hashed_text = calculate_hash(text.encode(), "sha1")
            st.write("SHA1 Hash:", hashed_text)
        if hash_sha256:
            hashed_text = calculate_hash(text.encode(), "sha256")
            st.write("SHA256 Hash:", hashed_text)
        if hash_sha512:
            hashed_text = calculate_hash(text.encode(), "sha512")
            st.write("SHA512 Hash:", hashed_text)

elif option == "File":
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        file_contents = file.read()

        st.write(f"You uploaded '{file.name}' ({len(file_contents)} bytes)")

        st.subheader("Choose a hash function:")
        hash_md5 = st.checkbox("MD5")
        hash_sha1 = st.checkbox("SHA1")
        hash_sha256 = st.checkbox("SHA256")
        hash_sha512 = st.checkbox("SHA512")

        if hash_md5:
            hashed_file = calculate_hash(file_contents, "md5")
            st.write("MD5 Hash:", hashed_file)
        if hash_sha1:
            hashed_file = calculate_hash(file_contents, "sha1")
            st.write("SHA1 Hash:", hashed_file)
        if hash_sha256:
            hashed_file = calculate_hash(file_contents, "sha256")
            st.write("SHA256 Hash:", hashed_file)
        if hash_sha512:
            hashed_file = calculate_hash(file_contents, "sha512")
            st.write("SHA512 Hash:", hashed_file)
