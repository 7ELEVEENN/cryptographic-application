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

        st.subheader("Choose hash functions:")
        hash_md5 = st.checkbox("MD5")
        hash_sha1 = st.checkbox("SHA1")
        hash_sha256 = st.checkbox("SHA256")
        hash_sha512 = st.checkbox("SHA512")

        hash_functions = []
        if hash_md5:
            hash_functions.append("md5")
        if hash_sha1:
            hash_functions.append("sha1")
        if hash_sha256:
            hash_functions.append("sha256")
        if hash_sha512:
            hash_functions.append("sha512")

        if hash_functions:
            st.write("Hash values:")
            for hash_type in hash_functions:
                hashed_text = calculate_hash(text.encode(), hash_type)
                st.write(f"{hash_type.upper()} Hash:", hashed_text)

elif option == "File":
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        file_contents = file.read()

        st.write(f"You uploaded '{file.name}' ({len(file_contents)} bytes)")

        st.subheader("Choose hash functions:")
        hash_md5 = st.checkbox("MD5")
        hash_sha1 = st.checkbox("SHA1")
        hash_sha256 = st.checkbox("SHA256")
        hash_sha512 = st.checkbox("SHA512")

        hash_functions = []
        if hash_md5:
            hash_functions.append("md5")
        if hash_sha1:
            hash_functions.append("sha1")
        if hash_sha256:
            hash_functions.append("sha256")
        if hash_sha512:
            hash_functions.append("sha512")

        if hash_functions:
            st.subheader("\nHash values:")
            for hash_type in hash_functions:
                hashed_file = calculate_hash(file_contents, hash_type)
                st.write(f"{hash_type.upper()} Hash:", hashed_file)
