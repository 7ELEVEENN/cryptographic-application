import streamlit as st
import hashlib

def calculate_hash(data, hash_type):
    hasher = hashlib.new(hash_type)
    hasher.update(data)
    return hasher.hexdigest()

def display_hash_values(hash_results):
    for hash_type, hashed_value in hash_results.items():
        st.write(f"**{hash_type.upper()} Hash:** `{hashed_value}`")

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

        # Display brief information about hash functions
        if hash_md5:
            st.info("MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function.")
        if hash_sha1:
            st.info("SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function.")
        if hash_sha256:
            st.info("SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function.")
        if hash_sha512:
            st.info("SHA-512 (Secure Hash Algorithm 512-bit) is a cryptographic hash function.")

        hash_functions = {}
        if hash_md5:
            hash_functions["md5"] = "MD5"
        if hash_sha1:
            hash_functions["sha1"] = "SHA1"
        if hash_sha256:
            hash_functions["sha256"] = "SHA256"
        if hash_sha512:
            hash_functions["sha512"] = "SHA512"

        if hash_functions:
            st.markdown("## Hash values:")  # Larger font size using Markdown syntax
            hash_results = {}
            for hash_type, label in hash_functions.items():
                hashed_text = calculate_hash(text.encode(), hash_type)
                hash_results[label] = hashed_text
            
            display_hash_values(hash_results)

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

        # Display brief information about hash functions
        if hash_md5:
            st.info("MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function.")
        if hash_sha1:
            st.info("SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function.")
        if hash_sha256:
            st.info("SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function.")
        if hash_sha512:
            st.info("SHA-512 (Secure Hash Algorithm 512-bit) is a cryptographic hash function.")

        hash_functions = {}
        if hash_md5:
            hash_functions["md5"] = "MD5"
        if hash_sha1:
            hash_functions["sha1"] = "SHA1"
        if hash_sha256:
            hash_functions["sha256"] = "SHA256"
        if hash_sha512:
            hash_functions["sha512"] = "SHA512"

        if hash_functions:
            st.markdown("## Hash values:")  # Larger font size using Markdown syntax
            hash_results = {}
            for hash_type, label in hash_functions.items():
                hashed_file = calculate_hash(file_contents, hash_type)
                hash_results[label] = hashed_file
            
            display_hash_values(hash_results)
