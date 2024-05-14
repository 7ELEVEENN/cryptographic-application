import streamlit as st
import hashlib

def calculate_hash(data, hash_type):
    hasher = hashlib.new(hash_type)
    hasher.update(data)
    return hasher.hexdigest()

def display_hash_values(hash_results):
    st.markdown("## Hash values:")  # Larger font size using Markdown syntax
    for hash_type, hashed_value in hash_results.items():
        st.write(f"**{hash_type.upper()} Hash:** `{hashed_value}`")

def hash_info(hash_type):
    if hash_type == "md5":
        return "MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function with a hash length of 16 bytes that produces a 32-character hexadecimal hash value."
    elif hash_type == "sha1":
        return "SHA-1 (Secure Hash Algorithm 1) is a cryptographic hash function with a hash length of 20 bytes that produces a 40-character hexadecimal hash value."
    elif hash_type == "sha256":
        return "SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function with a hash length of 32 bytes that produces a 64-character hexadecimal hash value."
    elif hash_type == "sha512":
        return "SHA-512 (Secure Hash Algorithm 512-bit) is a cryptographic hash function with a hash length of 64 bytes that produces a 128-character hexadecimal hash value."

st.title("Hashing Functions")
st.markdown("""<div style="background-color:#222831;padding:15px;border-radius:10px">
    <p style="text-align: justify; color: white;">Hashing functions are one-way mathematical functions that convert data into a unique, fixed-length string of characters. It helps in storing passwords securely in a database, it also ensures data integrity by indicating when data has been altered, as well as it organizes content and files in a way that increases efficiency.</p>
    </div>""", unsafe_allow_html=True)

option = st.radio("Choose input method:", ("Text", "File"))

if option == "Text":
    text = st.text_input("Enter text to hash:")
    if text:
        st.write("You entered:", text)

        st.subheader("Choose hash functions:")
        hash_functions = {}
        for hash_type in ["md5", "sha1", "sha256", "sha512"]:
            if st.checkbox(hash_type.upper()):
                hash_functions[hash_type] = hash_type.upper()
                st.info(hash_info(hash_type))

        if hash_functions:
            hash_results = {}
            for hash_type in hash_functions:
                hashed_text = calculate_hash(text.encode(), hash_type)
                hash_results[hash_type] = hashed_text
            
            display_hash_values(hash_results)

elif option == "File":
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        file_contents = file.read()

        st.write(f"You uploaded '{file.name}' ({len(file_contents)} bytes)")

        st.subheader("Choose hash functions:")
        hash_functions = {}
        for hash_type in ["md5", "sha1", "sha256", "sha512"]:
            if st.checkbox(hash_type.upper()):
                hash_functions[hash_type] = hash_type.upper()
                st.info(hash_info(hash_type))

        if hash_functions:
            hash_results = {}
            for hash_type in hash_functions:
                hashed_file = calculate_hash(file_contents, hash_type)
                hash_results[hash_type] = hashed_file
            
            display_hash_values(hash_results)
