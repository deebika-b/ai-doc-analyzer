import streamlit as st
import requests
import os

# --- PAGE CONFIG ---
st.set_page_config(page_title="AI SaaS Analyzer", layout="centered")

# --- DOCKER CONNECTIVITY LOGIC ---
# Inside Docker, 'backend' is the service name. Locally, it's '127.0.0.1'.
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

# Initialize session state for the security token
if "token" not in st.session_state:
    st.session_state.token = None

st.title("📄 AI SaaS Document Analyzer")

# --- SIDEBAR NAVIGATION ---
menu = ["Login", "Register"]
choice = st.sidebar.selectbox("User Menu", menu)

# --- REGISTRATION ---
if choice == "Register":
    st.subheader("Create Account")
    email = st.text_input("Email")
    password = st.text_input("Password", type='password')
    
    if st.button("Register"):
        try:
            # Note: We pass email and password as query parameters to match your backend logic
            res = requests.post(f"{BACKEND_URL}/register?email={email}&password={password}")
            if res.status_code == 200:
                st.success("Registration Success! Please switch to Login.")
            else:
                st.error(f"Error: {res.json().get('detail', 'Registration failed')}")
        except Exception as e:
            st.error(f"Connection Error: {e}")

# --- LOGIN ---
elif choice == "Login":
    st.subheader("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type='password')
    
    if st.button("Login"):
        # OAuth2 expects 'data' (form-encoded) with 'username' and 'password'
        login_payload = {"username": email, "password": password}
        try:
            res = requests.post(f"{BACKEND_URL}/login", data=login_payload)
            if res.status_code == 200:
                st.session_state.token = res.json()["access_token"]
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Invalid credentials. Did you register first?")
        except Exception as e:
            st.error(f"Backend unreachable at {BACKEND_URL}. Is it running?")

# --- MAIN APP (Authenticated Only) ---
if st.session_state.token:
    st.sidebar.divider()
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"token": None}))
    
    st.divider()
    st.subheader("Upload and Analyze")
    
    uploaded_file = st.file_uploader("Upload PDF", type=["pdf"])
    
    if st.button("Analyze Document"):
        if uploaded_file is not None:
            headers = {"Authorization": f"Bearer {st.session_state.token}"}
            
            with st.spinner("Uploading and Analyzing..."):
                # 1. Upload the file to the backend
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/pdf")}
                try:
                    up_res = requests.post(f"{BACKEND_URL}/upload", headers=headers, files=files)
                    
                    if up_res.status_code == 200:
                        doc_id = up_res.json()["id"]
                        
                        # 2. Request summarization for that specific document ID
                        sum_res = requests.post(f"{BACKEND_HOST if 'BACKEND_HOST' in locals() else BACKEND_URL}/summarize/{doc_id}", headers=headers)
                        
                        if sum_res.status_code == 200:
                            st.success("Analysis Complete!")
                            st.markdown("### AI Summary")
                            st.write(sum_res.json().get("summary"))
                        else:
                            st.error("AI summarization failed.")
                    else:
                        st.error(f"Upload failed: {up_res.status_code}")
                except Exception as e:
                    st.error(f"Connection lost: {e}")
        else:
            st.warning("Please select a PDF file first.")