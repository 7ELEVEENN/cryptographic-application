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
        hash_type = st.selectbox("Choose a hash function:", ("md5", "sha1", "sha256", "sha512"))
        hashed_text = calculate_hash(text.encode(), hash_type)

        st.write("Hash value:", hashed_text)

elif option == "File":
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        file_contents = file.read()
        hash_type = st.selectbox("Choose a hash function:", ("md5", "sha1", "sha256", "sha512"))
        hashed_file = calculate_hash(file_contents, hash_type)

        st.write("Hash value:", hashed_file)