import streamlit as st

st.title("Caesar Cipher")

text = st.text_area("Text:")
shift_keys_input = st.text_input("Shift Keys:")

if shift_keys_input:
    shift_keys = list(map(int, shift_keys_input.split()))
else:
    shift_keys = []

if st.button("Submit"):

    if not text or not shift_keys:
        st.write("Text and Shift Keys should not be empty.")
    else:
        st.write("")
        st.subheader("Output:")
        st.write("")

        def encrypt_decrypt(text, shift_keys, ifdecrypt):
            result = ""
            # Constraint
            assert 1 < len(shift_keys) <= len(text), "Length of shift keys is invalid"

            for i, char in enumerate(text):
                shift = shift_keys[i % len(shift_keys)]
                # Constraint: character accepted range
                if 32 <= ord(char) <= 125:
                    if ifdecrypt:
                        asc = ord(char) - shift
                    else:
                        asc = ord(char) + shift

                    while asc > 125:
                        asc -= 94
                    while asc < 32:
                        asc += 94

                    result += chr(asc)

                else:
                    result += char
                st.write(i, char, shift, result[i])
            return result

        # Example Usage
        enc = encrypt_decrypt(text, shift_keys, False)
        st.write("----------")
        dec = encrypt_decrypt(enc, shift_keys, True)
        st.write("----------")
        st.write("\nText:", text)
        st.write("Shift keys:", *shift_keys)
        st.write("Cipher:", enc)
        st.write("Decrypted text:", dec)
        st.balloons()
        st.snow()
