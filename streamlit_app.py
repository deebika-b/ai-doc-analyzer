import streamlit as st
import requests

st.set_page_config(page_title="AI Document Analyzer", layout="wide")
st.title("📄 AI Document Analyzer")

# Initialize session state for the security token
if "token" not in st.session_state:
    st.session_state["token"] = None

# --- SIDEBAR: LOGIN / REGISTER ---
with st.sidebar:
    st.header("🔑 Account Access")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    
    col1, col2 = st.columns(2)
    
    if col1.button("Login"):
        # Matches the 'login' endpoint in main.py
        data = {"username": email, "password": password}
        res = requests.post("http://127.0.0.1:8000/login", data=data)
        if res.status_code == 200:
            st.session_state["token"] = res.json()["access_token"]
            st.success("Logged in!")
            st.rerun()
        else:
            st.error("Invalid email or password")

    if col2.button("Register"):
        # Matches the 'register' endpoint in main.py
        res = requests.post(f"http://127.0.0.1:8000/register?email={email}&password={password}")
        if res.status_code == 200:
            st.success("Registered! You can now login.")
        else:
            st.error("Registration failed (Email might exist)")

# --- MAIN INTERFACE ---
if st.session_state["token"]:
    st.write(f"Logged in as: **{email}**")
    if st.button("Log Out"):
        st.session_state["token"] = None
        st.rerun()

    st.divider()
    
    uploaded_file = st.file_uploader("Upload a PDF for AI Analysis", type="pdf")

    if uploaded_file is not None:
        if st.button("Analyze & Summarize"):
            with st.spinner("Processing document..."):
                headers = {"Authorization": f"Bearer {st.session_state['token']}"}
                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/pdf")}
                
                # Step 1: Upload to Backend
                up_res = requests.post("http://127.0.0.1:8000/upload", headers=headers, files=files)
                
                if up_res.status_code == 200:
                    doc_id = up_res.json().get("id")
                    
                    # Step 2: Request Summary from AI
                    sum_res = requests.post(f"http://127.0.0.1:8000/summarize/{doc_id}", headers=headers)
                    
                    if sum_res.status_code == 200:
                        st.success("Done!")
                        st.subheader("AI Summary")
                        st.write(sum_res.json().get("summary"))
                    else:
                        st.error("AI summarization failed.")
                else:
                    st.error("Upload failed. Session might have expired.")
else:
    st.info("👈 Please Login or Register in the sidebar to begin.")