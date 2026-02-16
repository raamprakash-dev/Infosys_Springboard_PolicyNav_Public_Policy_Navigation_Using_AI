
import streamlit as st
import sqlite3
import bcrypt
import jwt
import datetime
import re
import time

SECRET_KEY = "super_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users ("
              "id INTEGER PRIMARY KEY AUTOINCREMENT,"
              "username TEXT UNIQUE,"
              "email TEXT UNIQUE,"
              "password BLOB,"
              "security_question TEXT,"
              "security_answer BLOB)")
    conn.commit()
    conn.close()

init_db()

# ================= JWT =================
def create_access_token(data):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except:
        return None

def is_valid_email(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return re.match(pattern, email)

# ================= DB FUNCTIONS =================
def create_user(username, email, password, question, answer):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    hashed_answer = bcrypt.hashpw(answer.lower().encode(), bcrypt.gensalt())
    try:
        c.execute("INSERT INTO users (username,email,password,security_question,security_answer) VALUES (?,?,?,?,?)",
                  (username, email, hashed_password, question, hashed_answer))
        conn.commit()
        return True
    except:
        return False
    finally:
        conn.close()

def authenticate_user(email, password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT username,password FROM users WHERE email=?", (email,))
    user = c.fetchone()
    conn.close()
    if user:
        username, hashed_password = user
        if bcrypt.checkpw(password.encode(), hashed_password):
            return username
        else:
            return "wrong_password"
    return None

def get_security_question(email):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT security_question FROM users WHERE email=?", (email,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def verify_security_answer(email, answer):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("SELECT security_answer FROM users WHERE email=?", (email,))
    result = c.fetchone()
    conn.close()
    if result:
        return bcrypt.checkpw(answer.lower().encode(), result[0])
    return False

def update_password(email, new_password):
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    c.execute("UPDATE users SET password=? WHERE email=?", (hashed_password, email))
    conn.commit()
    conn.close()

# ================= SESSION =================
if "page" not in st.session_state:
    st.session_state.page = "login"
if "token" not in st.session_state:
    st.session_state.token = None

st.set_page_config(page_title="Internship Portal", layout="centered")

# Remove Streamlit default header space
st.markdown(
    "<style>"
    "#MainMenu {visibility: hidden;}"
    "footer {visibility: hidden;}"
    "header {visibility: hidden;}"
    ".block-container {padding-top: 2rem;}"
    "body {background-color: #f4f6f9;}"
    ".card {background: white; padding: 40px; border-radius: 12px; "
    "box-shadow: 0 10px 30px rgba(0,0,0,0.1);}"
    ".stButton>button {width:100%; background-color:#2563eb; "
    "color:white; border-radius:8px; height:45px; font-weight:500;}"
    ".stButton>button:hover {background-color:#1e40af;}"
    "</style>",
    unsafe_allow_html=True
)

# ================= LOGIN =================
def login():

    st.markdown("<h2 style='text-align:center;'>Login</h2>", unsafe_allow_html=True)

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if not email:
            st.error("Please enter email")
        elif not password:
            st.error("Please enter password")
        else:
            result = authenticate_user(email, password)
            if result == "wrong_password":
                st.error("Password does not match")
            elif result:
                st.session_state.token = create_access_token({"email": email, "username": result})
                st.success("Login Successful")
                time.sleep(1)
                st.rerun()
            else:
                st.error("User not found")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Create Account"):
            st.session_state.page = "signup"
            st.rerun()
    with col2:
        if st.button("Forgot Password"):
            st.session_state.page = "forgot"
            st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

# ================= SIGNUP =================
def signup():
    
    st.markdown("<h2 style='text-align:center;'>Create Account</h2>", unsafe_allow_html=True)

    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")
    question = st.selectbox("Security Question",
        ["What is your favorite color?",
         "What is your pet's name?",
         "What is your birthplace?"])
    answer = st.text_input("Security Answer")

    if st.button("Register"):
        if not username:
            st.error("Please enter username")
        elif not email:
            st.error("Please enter email")
        elif not password:
            st.error("Please enter password")
        elif not answer:
            st.error("Please enter security answer")
        elif password != confirm:
            st.error("Passwords do not match")
        elif not is_valid_email(email):
            st.error("Invalid email format")
        elif create_user(username, email, password, question, answer):
            st.success("Account Created Successfully")
            time.sleep(1)
            st.session_state.page = "login"
            st.rerun()
        else:
            st.error("Username or Email already exists")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

# ================= FORGOT =================
def forgot():
   
    st.markdown("<h2 style='text-align:center;'>Reset Password</h2>", unsafe_allow_html=True)

    email = st.text_input("Registered Email")

    if st.button("Get Security Question"):
        question = get_security_question(email)
        if question:
            st.session_state.reset_email = email
            st.session_state.reset_question = question
        else:
            st.error("Email not found")

    if "reset_question" in st.session_state:
        st.info(st.session_state.reset_question)
        answer = st.text_input("Answer")
        new_password = st.text_input("New Password", type="password")

        if st.button("Reset Password"):
            if verify_security_answer(st.session_state.reset_email, answer):
                update_password(st.session_state.reset_email, new_password)
                st.success("Password Updated Successfully")
                time.sleep(1)
                st.session_state.page = "login"
                st.rerun()
            else:
                st.error("Incorrect answer")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

# ================= DASHBOARD =================
def dashboard():
    data = verify_token(st.session_state.token)
    if not data:
        st.session_state.token = None
        st.session_state.page = "login"
        st.rerun()

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown("<h2 style='text-align:center;'>Welcome " + data["username"] + "</h2>", unsafe_allow_html=True)

    if st.button("Logout"):
        st.session_state.token = None
        st.session_state.page = "login"
        st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

# ================= MAIN =================
if st.session_state.token:
    dashboard()
else:
    if st.session_state.page == "signup":
        signup()
    elif st.session_state.page == "forgot":
        forgot()
    else:
        login()
