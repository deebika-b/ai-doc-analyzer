import streamlit as st
import requests

st.set_page_config(page_title="AI SaaS Analyzer", layout="centered")

if "token" not in st.session_state:
    st.session_state.token = None

st.title("📄 AI SaaS Document Analyzer")

menu = ["Login", "Register"]
choice = st.sidebar.selectbox("User Menu", menu)

# --- REGISTRATION ---
if choice == "Register":
    st.subheader("Create Account")
    email = st.text_input("Email")
    password = st.text_input("Password", type='password')
    if st.button("Register"):
        # Match backend params
        res = requests.post(f"http://127.0.0.1:8000/register?email={email}&password={password}")
        if res.status_code == 200:
            st.success("Registration Success! Please switch to Login.")
        else:
            st.error(f"Error: {res.json().get('detail', 'Registration failed')}")

# --- LOGIN ---
elif choice == "Login":
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type='password')
    if st.button("Login"):
        # OAuth2 expects 'data' (form-data) with 'username' and 'password'
        login_payload = {"username": email, "password": password}
        res = requests.post("http://127.0.0.1:8000/login", data=login_payload)
        
        if res.status_code == 200:
            st.session_state.token = res.json()["access_token"]
            st.success("Logged in successfully!")
            st.rerun()
        else:
            st.error("Invalid credentials. Did you register first?")

# --- MAIN APP ---
if st.session_state.token:
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"token": None}))
    st.divider()
    
    uploaded_file = st.file_uploader("Upload PDF", type=["pdf"])
    if st.button("Analyze") and uploaded_file:
        headers = {"Authorization": f"Bearer {st.session_state.token}"}
        
        with st.spinner("Uploading and Analyzing..."):
            # 1. Upload
            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/pdf")}
            up_res = requests.post("http://127.0.0.1:8000/upload", headers=headers, files=files)
            
            if up_res.status_code == 200:
                doc_id = up_res.json()["id"]
                # 2. Summarize
                sum_res = requests.post(f"http://127.0.0.1:8000/summarize/{doc_id}", headers=headers)
                if sum_res.status_code == 200:
                    st.success("Summary Generated!")
                    st.write(sum_res.json().get("summary"))
                else:
                    st.error("Summarization failed.")
            else:
                st.error("Upload failed.")