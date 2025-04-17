# app.py
import streamlit as st
import bcrypt

st.set_page_config(page_title="🔐 Password Hasher & Verifier", layout="centered")

st.title("🔐 Secure Password Hasher & Verifier")
st.markdown("Built with `bcrypt` | By Uday")

tab1, tab2 = st.tabs(["🔑 Generate Hash", "✅ Verify Password"])

with tab1:
    password_to_hash = st.text_input("Enter password to hash", type="password")
    if st.button("Generate Hash"):
        if password_to_hash:
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password_to_hash.encode(), salt).decode()
            st.success("Hashed Password Generated:")
            st.code(hashed_password)
        else:
            st.warning("⚠️ Please enter a password.")

with tab2:
    original_password = st.text_input("Enter your password", type="password")
    hashed_input = st.text_input("Enter the hashed password")
    if st.button("Verify Password"):
        if original_password and hashed_input:
            try:
                result = bcrypt.checkpw(original_password.encode(), hashed_input.encode())
                if result:
                    st.success("✅ Password Verified Successfully!")
                else:
                    st.error("❌ Password does not match.")
            except Exception as e:
                st.error(f"⚠️ Error verifying password: {e}")
        else:
            st.warning("⚠️ Please enter both password and hash.")
