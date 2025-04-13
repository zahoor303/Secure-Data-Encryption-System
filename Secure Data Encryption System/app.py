# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# # === Streamlit Setup ===
# st.set_page_config(page_title="Secure Data Encryption System", page_icon="🛡️")

# # === Session State Initialization ===
# if "key" not in st.session_state:
#     st.session_state.key = Fernet.generate_key()

# if "stored_data" not in st.session_state:
#     st.session_state.stored_data = {}

# if "failed_attempts" not in st.session_state:
#     st.session_state.failed_attempts = 0

# cipher = Fernet(st.session_state.key)

# # === Utility Functions ===
# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()

# def encrypt_data(text):
#     return cipher.encrypt(text.encode()).decode()

# def decrypt_data(encrypted_text, passkey):
#     hashed = hash_passkey(passkey)
#     data = st.session_state.stored_data
#     if encrypted_text in data and data[encrypted_text]["passkey"] == hashed:
#         st.session_state.failed_attempts = 0
#         return cipher.decrypt(encrypted_text.encode()).decode()
#     else:
#         st.session_state.failed_attempts += 1
#         return None

# def reset_attempts():
#     st.session_state.failed_attempts = 0

# # === UI Header ===
# st.title("🛡️ Secure Data Encryption System")

# # === Navigation ===
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.radio("📁 Navigation", menu)

# # === Pages ===

# if choice == "Home":
#     st.subheader("🏠 Welcome!")
#     st.markdown("""
#     - 🔐 **Encrypt and store** your sensitive data securely.
#     - 🔑 Use a passkey to **decrypt** data.
#     - ⛔ After 3 failed attempts, you'll be redirected to login.
#     """)

# elif choice == "Store Data":
#     st.subheader("📂 Store New Data")

#     user_data = st.text_area("Enter the data you want to encrypt")
#     passkey = st.text_input("Create a passkey", type="password")

#     if st.button("🔐 Encrypt & Save"):
#         if user_data and passkey:
#             encrypted = encrypt_data(user_data)
#             hashed = hash_passkey(passkey)
#             st.session_state.stored_data[encrypted] = {
#                 "encrypted_text": encrypted,
#                 "passkey": hashed
#             }
#             st.success("✅ Data encrypted and stored successfully!")
#             st.code(encrypted, language="text")
#         else:
#             st.error("⚠️ Both data and passkey are required!")

# elif choice == "Retrieve Data":
#     st.subheader("🔍 Retrieve Encrypted Data")

#     if st.session_state.failed_attempts >= 3:
#         st.warning("⛔ Too many failed attempts. Please reauthorize.")
#         st.switch_page("Login")  # Or handle redirect manually

#     encrypted_text = st.text_area("Paste your encrypted text here")
#     passkey = st.text_input("Enter your passkey", type="password")

#     if st.button("🔓 Decrypt"):
#         if encrypted_text and passkey:
#             result = decrypt_data(encrypted_text, passkey)
#             if result:
#                 st.success("✅ Decryption successful!")
#                 st.code(result, language="text")
#             else:
#                 remaining = 3 - st.session_state.failed_attempts
#                 st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
#                 if remaining <= 0:
#                     st.warning("🔒 Locked out. Redirecting to Login page...")
#                     st.experimental_rerun()
#         else:
#             st.error("⚠️ Please enter both fields.")

# elif choice == "Login":
#     st.subheader("🔑 Admin Reauthorization")

#     admin_pass = st.text_input("Enter admin password:", type="password")

#     if st.button("🔁 Reauthorize"):
#         if admin_pass == "admin123":
#             reset_attempts()
#             st.success("✅ Access restored! You can now try again.")
#             st.experimental_rerun()
#         else:
#             st.error("❌ Incorrect admin password.")
# st.session_state.failed_attempts += 1





import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet

# File for saving encrypted data
DATA_FILE = "data.json"

# Load or initialize data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

data = load_data()

# Generate app-wide encryption key
if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()
cipher = Fernet(st.session_state.key)

# Hash passkey using PBKDF2
def hash_passkey(passkey, salt):
    return hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt.encode(), 100000).hex()

# UI Title
st.set_page_config(page_title="🔐 Secure Data Vault", page_icon="🛡️")
st.title("🛡️ Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data"]
choice = st.sidebar.radio("📁 Navigate", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome to Your Secure Vault")
    st.write("""
    🔐 Store & retrieve data safely using encryption + passkey  
    🔑 Each user is identified by a **username**  
    ⏱️ Locked out for 30 seconds after 3 failed attempts
    """)

# Store Data Page
elif choice == "Store Data":
    st.subheader("📦 Store Encrypted Data")

    username = st.text_input("👤 Enter your username")
    text = st.text_area("🔏 Enter text to encrypt")
    passkey = st.text_input("🔑 Create a passkey", type="password")

    if st.button("🔐 Encrypt & Save"):
        if username and text and passkey:
            salt = os.urandom(16).hex()
            hashed = hash_passkey(passkey, salt)
            encrypted = cipher.encrypt(text.encode()).decode()

            data[username] = {
                "encrypted_text": encrypted,
                "passkey": hashed,
                "salt": salt,
                "failed_attempts": 0,
                "lockout_time": 0
            }

            save_data(data)
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ All fields are required!")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Encrypted Data")

    username = st.text_input("👤 Enter your username")
    passkey = st.text_input("🔑 Enter your passkey", type="password")

    if st.button("🔓 Decrypt"):
        if username and passkey:
            user = data.get(username)

            if not user:
                st.error("❌ User not found!")
            else:
                current_time = time.time()
                locked = current_time < user.get("lockout_time", 0)

                if locked:
                    seconds_left = int(user["lockout_time"] - current_time)
                    st.error(f"⏱️ Locked out. Try again in {seconds_left} seconds.")
                else:
                    hashed = hash_passkey(passkey, user["salt"])
                    if hashed == user["passkey"]:
                        decrypted = cipher.decrypt(user["encrypted_text"].encode()).decode()
                        st.success("✅ Decryption successful!")
                        st.code(decrypted, language="text")
                        user["failed_attempts"] = 0
                        user["lockout_time"] = 0
                        save_data(data)
                    else:
                        user["failed_attempts"] += 1
                        attempts_left = 3 - user["failed_attempts"]

                        if user["failed_attempts"] >= 3:
                            user["lockout_time"] = time.time() + 30  # 30 sec lockout
                            st.error("🔒 Too many failed attempts! Locked for 30 seconds.")
                        else:
                            st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                        save_data(data)
        else:
            st.error("⚠️ Username and passkey are required!")
else:
    st.error("❌ Invalid choice! Please select a valid option from the sidebar.")