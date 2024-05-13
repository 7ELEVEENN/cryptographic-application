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
        st.markdown("SHA-512": """<div style="background-color:#222831;padding:10px;border-radius:10px">
    <p style="text-align: justify; color: white;">
SHA-512 is part of the SHA-2 family and produces a 512-bit hash value. It offers even greater collision resistance than SHA-256. SHA-512 is used in various security protocols, ensuring data integrity and authenticity. It’s commonly employed in TLS, SSL, and other cryptographic applications.</p>
    </div>""")
        hash_md5 = st.checkbox("MD5")
        hash_sha1 = st.checkbox("SHA1")
        hash_sha256 = st.checkbox("SHA256")
        hash_sha512 = st.checkbox("SHA512")

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
            st.write("Hash values:")
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
            st.write("\nHash values:")
            hash_results = {}
            for hash_type, label in hash_functions.items():
                hashed_file = calculate_hash(file_contents, hash_type)
                hash_results[label] = hashed_file
            
            display_hash_values(hash_results)
