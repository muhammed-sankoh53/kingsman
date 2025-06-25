import streamlit as st
import sqlite3
import os
import hashlib
from datetime import datetime
import io

# --- Database Setup ---
DB_PATH = "file_data.db"

def create_tables():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            phone TEXT,
            email TEXT UNIQUE,
            password_hash TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            filetype TEXT,
            content BLOB,
            upload_time TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

create_tables()

# --- Utility Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(name, phone, email, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (name, phone, email, password_hash) VALUES (?, ?, ?, ?)",
                  (name, phone, email, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def authenticate_user(email, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, password_hash FROM users WHERE email=?", (email,))
    user = c.fetchone()
    conn.close()
    if user and user[1] == hash_password(password):
        return user[0]
    return None

def save_file(user_id, filename, filetype, content):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO files (user_id, filename, filetype, content, upload_time) VALUES (?, ?, ?, ?, ?)",
              (user_id, filename, filetype, content, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_all_files():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT files.id, users.name, users.email, files.filename, files.filetype, files.upload_time
        FROM files
        JOIN users ON files.user_id = users.id
        ORDER BY files.upload_time DESC
    ''')
    files = c.fetchall()
    conn.close()
    return files

def get_file_content(file_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT filetype, content FROM files WHERE id=?", (file_id,))
    file = c.fetchone()
    conn.close()
    return file

# --- Streamlit UI ---
st.set_page_config(page_title="Multi-Code File Saver", layout="wide")

# st.markdown("""
#     <style>
#     .main {background-color: #f0f2f6;}
#     .stButton>button {background-color: #4CAF50; color: white;}
#     .stTextInput>div>div>input {background-color: #e8f0fe;}
#     .stFileUploader>div>div {background-color: #e8f0fe;}
#     .stDataFrame {background-color: #fff;}
#     </style>
# """, unsafe_allow_html=True)

st.title("📁 Multi-Code File Saver & Viewer")
st.write("Save and share your code or documents securely. All files are visible to everyone, but only owners can manage their uploads.")

menu = st.sidebar.selectbox("Menu", ["Register", "Login", "View Files", "My code"])

if menu == "Register":
    st.header("Register")
    with st.form("register_form"):
        name = st.text_input("Name")
        phone = st.text_input("Phone Number")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Register")
        if submit:
            if register_user(name, phone, email, password):
                st.success("Registration successful! Please login.")
            else:
                st.error("Email already registered.")

elif menu == "Login":
    st.header("Login")
    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        if submit:
            user_id = authenticate_user(email, password)
            if user_id:
                st.session_state['user_id'] = user_id
                st.session_state['email'] = email
                st.success("Login successful!")
            else:
                st.error("Invalid credentials.")

    if 'user_id' in st.session_state:
        st.header("Upload File")
        with st.form("upload_form"):
            filename = st.text_input("File Name (with extension)")
            filetype = st.selectbox("File Type", ["html", "py", "cpp", "jsx", "js", "txt"])
            if filetype == "txt":
                file = st.file_uploader("Upload TXT file", type=["txt"])
                content = file.read() if file else None
            else:
                content = st.text_area("Paste your code/content here")
                content = content.encode() if content else None
            upload = st.form_submit_button("Save File")
            if upload and filename and content:
                save_file(st.session_state['user_id'], filename, filetype, content)
                st.success("File saved successfully!")

elif menu == "View Files":
    st.header("All Uploaded Files")
    files = get_all_files()
    if files:
        for file in files:
            file_id, name, email, filename, filetype, upload_time = file
            with st.expander(f"{filename} ({filetype}) by {name} [{email}] at {upload_time}"):
                if st.button("View Content", key=f"view_{file_id}"):
                    filetype, content = get_file_content(file_id)
                    # Only display text/code files
                    try:
                        st.code(content.decode(), language=filetype if filetype != "jsx" else "javascript")
                    except Exception:
                        st.warning("Cannot display this file type.")
    else:
        st.info("No files uploaded yet.")   
#############################################################
elif menu == "My code":
    # --- User File Management Section ---
    if 'user_id' not in st.session_state:
        st.warning("Please login to view and manage your files.")
    else:
        st.header("My Code Files")
        user_id = st.session_state['user_id']

        # Fetch user's files
        def get_user_files(user_id):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                SELECT id, filename, filetype, upload_time
                FROM files
                WHERE user_id=?
                ORDER BY upload_time DESC
            ''', (user_id,))
            files = c.fetchall()
            conn.close()
            return files

        # Delete file
        def delete_file(file_id, user_id):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM files WHERE id=? AND user_id=?", (file_id, user_id))
            conn.commit()
            conn.close()

        # Update file content
        def update_file_content(file_id, user_id, new_content):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE files SET content=?, upload_time=? WHERE id=? AND user_id=?",
                    (new_content, datetime.now().isoformat(), file_id, user_id))
            conn.commit()
            conn.close()

        # Lock/Unlock file (simple password protection)
        def set_file_lock(file_id, user_id, lock_hash):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("ALTER TABLE files ADD COLUMN lock_hash TEXT")  # Will fail if already exists, ignore error
            try:
                c.execute("UPDATE files SET lock_hash=? WHERE id=? AND user_id=?", (lock_hash, file_id, user_id))
                conn.commit()
            except Exception:
                pass
            conn.close()

        def get_file_lock_hash(file_id):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            try:
                c.execute("SELECT lock_hash FROM files WHERE id=?", (file_id,))
                row = c.fetchone()
                return row[0] if row else None
            except Exception:
                return None
            finally:
                conn.close()

        files = get_user_files(user_id)
        if not files:
            st.info("You have not uploaded any files yet.")
        else:
            for file in files:
                file_id, filename, filetype, upload_time = file
                with st.expander(f"{filename} ({filetype}) - Uploaded at {upload_time}"):
                    # Lock/Unlock logic
                    lock_hash = get_file_lock_hash(file_id)
                    if lock_hash:
                        unlock_pw = st.text_input(f"Enter password to unlock '{filename}'", type="password", key=f"unlock_{file_id}")
                        if st.button("Unlock", key=f"unlock_btn_{file_id}"):
                            if hash_password(unlock_pw) == lock_hash:
                                st.session_state[f'unlocked_{file_id}'] = True
                            else:
                                st.error("Incorrect password.")
                    if not lock_hash or st.session_state.get(f'unlocked_{file_id}', False):
                        # Show content
                        filetype_db, content = get_file_content(file_id)
                        try:
                            st.code(content.decode(), language=filetype_db if filetype_db != "jsx" else "javascript")
                        except Exception:
                            st.warning("Cannot display this file type.")

                        # Copy to clipboard (Streamlit can't access clipboard directly, but can show content to copy)
                        st.text_area("Copy your code below:", value=content.decode(), key=f"copy_{file_id}")

                        # Edit/Paste (update)
                        with st.form(f"edit_form_{file_id}"):
                            new_content = st.text_area("Edit your code and save changes:", value=content.decode())
                            save_edit = st.form_submit_button("Save Changes")
                            if save_edit:
                                update_file_content(file_id, user_id, new_content.encode())
                                st.success("File updated. Please refresh to see changes.")

                        # Delete
                        if st.button("Delete File", key=f"delete_{file_id}"):
                            delete_file(file_id, user_id)
                            st.success("File deleted. Please refresh to see changes.")

                        # Lock file
                        if not lock_hash:
                            lock_pw = st.text_input(f"Set password to lock '{filename}'", type="password", key=f"lock_{file_id}")
                            if st.button("Lock File", key=f"lock_btn_{file_id}"):
                                if lock_pw:
                                    set_file_lock(file_id, user_id, hash_password(lock_pw))
                                    st.success("File locked. Please refresh to see changes.")
                                else:
                                    st.warning("Please enter a password to lock the file.")
                    else:
                        st.info("This file is locked. Enter password to unlock.")