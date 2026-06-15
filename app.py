# app.py - Secure HIE with Enhanced AES-ECDH-ECDSA + Key Confirmation + File-Level Consent
import streamlit as st
import time
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from datetime import datetime
import secrets
import json
import os
import sqlite3

# --- Import custom modules ---
from crypto_utils import *
from db_sim import (USERS, PATIENTS, get_user_by_id, authenticate, init_db,
                    add_provider_file, get_patient_files, create_request, update_request,
                    get_request, get_patient_requests, get_provider_requests, DB_PATH)
from logger import log_metrics, read_logs, log_security_event, read_security_logs, LOG_FILE, SECURITY_LOG_FILE

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Secure HIE System",
    page_icon="🏥",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS ---
def load_css():
    st.markdown("""
    <style>
   .main-header {
        background: linear-gradient(90deg, #0066CC 0%, #004499 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
   .main-header h1 {
        color: white!important;
        margin: 0;
        font-size: 2.2rem;
    }
   .main-header p {
        color: #E0E0E0;
        margin: 0.5rem 0 0 0;
        font-size: 1.1rem;
    }
   .login-container {
        max-width: 400px;
        margin: 2rem auto;
        padding: 2rem;
        border: 1px solid #ddd;
        border-radius: 10px;
        background-color: #f9f9f9;
    }
   .stButton>button {
        width: 100%;
        border-radius: 8px;
        font-weight: 600;
    }
    </style>
    """, unsafe_allow_html=True)

load_css()

# --- HELPER: Parse decrypted string to dict ---
def parse_decrypted_to_dict(decrypted_str):
    if not decrypted_str:
        return {}
    try:
        pairs = decrypted_str.split('|')
        return {k: v for k, v in (pair.split(':', 1) for pair in pairs)}
    except:
        return {"raw_data": decrypted_str}

# --- SESSION STATE INIT ---
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'user_data' not in st.session_state:
    st.session_state.user_data = None
if 'signing_keys' not in st.session_state:
    st.session_state.signing_keys = {}
    for uid in USERS.keys():
        priv, pub = generate_signing_keypair()
        st.session_state.signing_keys[uid] = {"priv": priv, "pub": pub}
if 'provider_temp_keys' not in st.session_state:
    st.session_state.provider_temp_keys = {} # Store ephemeral keys per request_id for PFS

# --- LOGIN PAGE ---
if not st.session_state.authenticated:
    st.markdown("""
    <div class="main-header">
        <h1>🏥 Secure Health Information Exchange System</h1>
        <p>Enhanced AES-ECDH-ECDSA + Key Confirmation + File-Level Consent</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        st.subheader("🔐 System Login")
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="e.g., dr.garcia")
            password = st.text_input("Password", type="password", placeholder="Enter password")
            login_btn = st.form_submit_button("Login", type="primary", use_container_width=True)

            if login_btn:
                uid, user_data = authenticate(username, password)
                if uid:
                    st.session_state.authenticated = True
                    st.session_state.user_id = uid
                    st.session_state.user_data = user_data
                    st.success(f"Welcome, {user_data['name']}!")
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("Invalid username or password")
        st.markdown('</div>', unsafe_allow_html=True)
        with st.expander("📋 Demo Credentials"):
            st.code("HP001_DR_GARCIA / Cardio2026!\nPT001_M_SANTOS / Patient123!\nADMIN / Admin2026!")
    st.stop()

# --- AUTHENTICATED USER ---
user_id = st.session_state.user_id
user_data = st.session_state.user_data

st.markdown("""
<div class="main-header">
    <h1>🏥 Secure Health Information Exchange Prototype</h1>
    <p>Enhanced AES-256-GCM + ECDH-P256 + ECDSA + Key Confirmation + File-Level Consent</p>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
st.sidebar.header(f"👤 {user_data['name']}")
st.sidebar.caption(f"Role: {user_data['role']} | ID: {user_id}")
if user_data['role'] == "Healthcare Provider":
    st.sidebar.caption(f"{user_data['specialty']} | {user_data['hospital']}")
elif user_data['role'] == "Patient":
    st.sidebar.caption(f"Record: {user_data['record_id']}")

st.sidebar.divider()
if st.sidebar.button("🚪 Logout", use_container_width=True):
    st.session_state.authenticated = False
    st.session_state.user_id = None
    st.session_state.user_data = None
    st.rerun()

st.sidebar.divider()
st.sidebar.info("**Prototype Note:** Using simulated patient data per ethical guidelines.")

# --- MAIN CONTENT BY ROLE ---

# ==================== HEALTHCARE PROVIDER PORTAL ====================
if user_data['role'] == "Healthcare Provider":
    st.header("👨⚕ Healthcare Provider Portal")
    st.caption(f"Welcome, {user_data['name']} | {user_data['specialty']} | {user_data['hospital']}")

    # FILE UPLOAD SECTION - MOVED OUTSIDE REQUEST BUTTON
    with st.expander("📤 Upload Patient Medical File", expanded=False):
        st.caption("Upload files and associate with a specific patient")

        upload_patient = st.selectbox(
            "Select Patient",
            options=list(PATIENTS.keys()),
            format_func=lambda x: PATIENTS[x]['name'],
            key="upload_patient_select"
        )

        uploaded_file = st.file_uploader(
            "Choose file",
            type=['pdf', 'jpg', 'png', 'docx', 'txt'],
            key="file_upload"
        )

        file_type = st.selectbox(
            "File Type",
            ["Lab Result", "Prescription", "Medical Imaging", "Consultation Note", "Discharge Summary"],
            key="file_type_select"
        )

        file_desc = st.text_input("File Description", placeholder="e.g., Blood Test - CBC Panel")

        if st.button("Upload File") and uploaded_file is not None:
            file_id = f"FILE-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
            file_content = uploaded_file.read()

            add_provider_file(
                file_id=file_id,
                provider_id=user_id,
                patient_id=upload_patient,
                file_name=uploaded_file.name,
                file_type=file_type,
                description=file_desc,
                file_content=file_content
            )
            st.success(f"✅ File '{uploaded_file.name}' uploaded for {PATIENTS[upload_patient]['name']}")

    st.divider()
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Request Patient Data Access")
        patient_options = {f"{data['name']} ({pid})": pid for pid, data in PATIENTS.items()}
        selected_patient = st.selectbox("Select Patient", list(patient_options.keys()))
        patient_id = patient_options[selected_patient]

        # SHOW AVAILABLE FILES TO REQUEST
        available_files = get_patient_files(patient_id, user_id)
        if available_files:
            st.write("**Select files to request:**")
            requested_file_ids = []
            for file_id, file_name, file_type, file_desc, file_size, uploaded_at in available_files:
                if st.checkbox(f"[{file_type}] {file_name} - {file_desc}", key=f"req_file_{file_id}"):
                    requested_file_ids.append(file_id)
        else:
            st.warning("No files uploaded for this patient yet. Upload files first.")
            requested_file_ids = []

        if st.button("🔐 Request Access", type="primary", disabled=len(requested_file_ids)==0):
            req_id = f"REQ-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            start_time = time.perf_counter()
            st.session_state[f'req_start_{req_id}'] = start_time

            # 1. Generate ephemeral ECDH keypair - store in temp for PFS
            provider_priv, provider_pub = generate_ecdh_keypair()
            provider_pub_bytes = serialize_public_key(provider_pub)
            st.session_state.provider_temp_keys[req_id] = provider_priv # Store for later decryption

            # 2. Generate nonce for replay protection
            nonce = secrets.token_bytes(16)

            # 3. Sign ECDH pubkey + nonce
            provider_signing_priv = st.session_state.signing_keys[user_id]["priv"]
            signature = sign_ecdh_pubkey(provider_signing_priv, provider_pub_bytes, nonce)

            create_request(
                request_id=req_id,
                provider_id=user_id,
                patient_id=patient_id,
                provider_pub_key=provider_pub_bytes,
                provider_signature=signature,
                nonce=nonce.hex()
            )

            # Store requested files
            update_request(
                request_id=req_id,
                selected_files=json.dumps(requested_file_ids)
            )

            log_metrics(user_id, "Request Sent", 0.0, req_id, patient_id, user_id)
            st.success(f"Request {req_id} sent for {len(requested_file_ids)} file(s). ECDH key signed with ECDSA.")
            st.info("⏳ Waiting for patient approval...")
            time.sleep(1)
            st.rerun()

    with col2:
        st.subheader("My Active Requests")
        my_requests = get_provider_requests(user_id)

        if my_requests:
            for req in my_requests:
                req_id = req['request_id']
                with st.container(border=True):
                    patient_name = PATIENTS[req['patient_id']]['name']
                    st.write(f"**{req_id}** → {patient_name}")
                    st.write(f"Status: `{req['status']}`")

                    if req['status'] == "Approved":
                        st.success(f"Access Time: {req.get('access_time', 0):.4f}s")
                        if req.get('signature_verified'):
                            st.success("✅ Patient signature verified")
                        if req.get('key_confirmation_verified'):
                            st.success("✅ Key confirmation passed")

                        # DECRYPT APPROVED FILES
                        provider_priv = st.session_state.provider_temp_keys.get(req_id)
                        if provider_priv and req.get('encrypted_payload'):
                            patient_pub = deserialize_public_key(req['patient_pub_key'])

                            salt = req.get('salt')
                            aes_key, _, _ = derive_shared_key_enhanced(provider_priv, patient_pub, salt=salt)

                            #aad = req['aad_used']
                            aad = req.get('aad_used')
                            if not aad:
                                st.error("⚠️ Cannot decrypt: AAD not found in database. This request was created before AAD storage was implemented.")
                                st.caption("Delete this request and create a new one.")
                                st.stop()
                            
                            st.caption(f"Decrypting with AAD: {aad}")
    
                            try:
                                            # TIME THE DECRYPTION
                                decryption_start = time.perf_counter()
                                decrypted_json = aes_decrypt_enhanced(aes_key, req['encrypted_payload'], aad)
                                decryption_end = time.perf_counter()
                                decryption_time = decryption_end - decryption_start
            
                                # LOG IT IMMEDIATELY AFTER SUCCESS
                                log_metrics(user_id, "Decryption Time - File Decryption", decryption_time, req_id, req['patient_id'], user_id)
                                decrypted_json = aes_decrypt_enhanced(aes_key, req['encrypted_payload'], aad)

                                decrypted_data = json.loads(decrypted_json)

                                st.success(f"✅ Decryption successful | Decrypt Time: {decryption_time:.4f}s")

                                st.write("**Decrypted Files:**")
                                for file_info in decrypted_data['selected_files']:
                                    st.download_button(
                                        f"📥 {file_info['file_name']}",
                                        bytes.fromhex(file_info['content']),
                                        file_info['file_name'],
                                        key=f"dl_{req_id}_{file_info['file_id']}"
                                    )
                            except ValueError as e:
                                
                                st.error(f"⚠️ Decryption failed: {e}")
                                st.write("**Debug info:**")
                                st.write(f"Expected AAD: `{aad}`")
                                st.write(f"Payload size: {len(req['encrypted_payload'])} bytes")
                                st.caption("If AAD looks correct, the ciphertext may be corrupted")
                                st.stop()


                        with st.expander("🔍 Show Encryption Details"):
                            st.write("**1. Encrypted Payload (AES-256-GCM + AAD)**")
                            st.code(req['encrypted_payload'][:64].hex() + "...", language="text")
                            st.write("**2. Key Confirmation MAC**")
                            st.code(req.get('key_confirmation_mac', b'').hex(), language="text")
                        
                        

                    elif req['status'] == "Denied":
                        st.error("Access Denied by Patient")
                        with st.expander("🔍 Denial Details - Audit Trail"):
                            st.write("**Request ID:**", req_id)
                            st.write("**Denied At:**", req.get('denied_at', 'N/A'))
                            st.write("**Reason:**", req.get('denial_reason', 'Patient declined'))
                            st.write("**Security Alerts:**", req.get('security_alerts', '[]'))
                            st.code("Encrypted Payload: [NEVER GENERATED]", language="text")
        else:
            st.info("No active requests")

# ==================== PATIENT PORTAL ====================
elif user_data['role'] == "Patient":
    st.header("🧑🦰 Patient Portal")
    st.caption(f"Welcome, {user_data['name']} | You control access to your health data")

    # NEW: SHOW PATIENT'S OWN COMPLETE RECORD
    with st.expander("📋 My Personal Health Information", expanded=True):
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Basic Details")
            st.write(f"**Full Name:** {user_data.get('name', 'N/A')}")
            st.write(f"**Patient ID:** {user_id}")
            st.write(f"**Record ID:** {user_data.get('record_id', 'N/A')}")
            st.write(f"**Username:** {user_id}")  
            st.write(f"**Role:** {user_data.get('role', 'N/A')}")
            
        with col2:
            st.subheader("Medical Profile")
            my_record = PATIENTS[user_id]
            for key, value in my_record.items():
                if key not in ['encrypted_data', 'name', 'record_id']:  # Skip duplicates
                    st.write(f"**{key.replace('_', ' ').title()}:** {value}")

    st.divider()

    # NEW: SHOW ALL MY FILES IN THE SYSTEM
    st.subheader("📁 My Medical Files on Record")
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Check what columns actually exist first
        c.execute("PRAGMA table_info(provider_files)")
        columns = [col[1] for col in c.fetchall()]

        # Build query based on existing columns
        base_cols = "file_id, file_name, file_type, file_description, provider_id"
        if 'file_size' in columns:
            base_cols += ", file_size"
        if 'uploaded_at' in columns:
            base_cols += ", uploaded_at"

        c.execute(f"""
            SELECT {base_cols}
            FROM provider_files
            WHERE patient_id =?
            ORDER BY file_id DESC
        """, (user_id,))
        my_files = c.fetchall()
        conn.close()

        if my_files:
            st.write(f"**Total files stored:** {len(my_files)}")

            # Group by provider
            files_by_provider = {}
            for file_data in my_files:
                file_id = file_data[0]
                fname = file_data[1]
                ftype = file_data[2]
                desc = file_data[3]
                prov_id = file_data[4]
                fsize = file_data[5] if len(file_data) > 5 else "N/A"
                uploaded = file_data[6] if len(file_data) > 6 else "N/A"

                provider_name = USERS[prov_id]['name'] if prov_id in USERS else "Unknown"
                if provider_name not in files_by_provider:
                    files_by_provider[provider_name] = []
                files_by_provider[provider_name].append((file_id, fname, ftype, desc, fsize, uploaded, prov_id))

            for provider_name, files in files_by_provider.items():
                with st.expander(f"🏥 {provider_name} - {len(files)} file(s)"):
                    for file_id, fname, ftype, desc, fsize, uploaded, prov_id in files:
                        col1, col2 = st.columns([3, 2])
                        with col1:
                            st.write(f"**{fname}**")
                            st.caption(f"{desc}")
                        with col2:
                            st.write(f"Type: `{ftype}`")
                            if fsize!= "N/A":
                                st.caption(f"Size: {fsize} bytes")
                            if uploaded!= "N/A":
                                st.caption(f"Uploaded: {str(uploaded)[:10]}")
        else:
            st.info("No medical files have been uploaded for you yet.")
    except Exception as e:
        st.error(f"Could not load files: {e}")
        st.caption("Check if provider_files table exists in database")

    st.divider()


    st.subheader("Incoming Access Requests")
    my_requests = get_patient_requests(user_id)

    if my_requests:
        for req in my_requests:
            req_id = req['request_id']
            provider = get_user_by_id(req['provider_id'])
            with st.container(border=True):
                st.write(f"**Request {req_id}** from {provider['name']}")
                st.write(f"Specialty: {provider['specialty']} | Hospital: {provider['hospital']}")
                st.write(f"Requested at: {req['timestamp']}")

                # LOAD AVAILABLE FILES FROM THIS PROVIDER
                available_files = get_patient_files(user_id, req['provider_id'])
                requested_file_ids = json.loads(req['selected_files']) if req['selected_files'] else []

                if not available_files:
                    st.warning("No files available from this provider")
                    continue

                # GRANULAR CONSENT - PATIENT SELECTS FILES
                st.write("**Provider requested these files. Select which to share:**")
                approved_files = []
                for file_id, file_name, file_type, file_desc, file_size, uploaded_at in available_files:
                    if file_id in requested_file_ids:
                        if st.checkbox(
                            f"[{file_type}] {file_name} - {file_desc} ({file_size} bytes)",
                            key=f"approve_file_{req_id}_{file_id}"
                        ):
                            approved_files.append(file_id)

                st.write(f"Selected: {len(approved_files)}/{len(requested_file_ids)} requested files")

                # ATTACK SIMULATION TOGGLE
                st.divider()
                st.write("**🔬 Security Testing - For Thesis Defense Only**")
                col_sim1, col_sim2 = st.columns(2)
                with col_sim1:
                    simulate_mitm = st.checkbox("🎭 Simulate MITM: Corrupt Signature", key=f"mitm_{req_id}")
                with col_sim2:
                    simulate_keyfail = st.checkbox("🎭 Simulate Key Mismatch", key=f"keyfail_{req_id}")

                # Verify provider signature
                provider_signing_pub = st.session_state.signing_keys[req['provider_id']]["pub"]
                provider_signature = req['provider_signature']
                if simulate_mitm:
                    provider_signature = os.urandom(64)
                    st.warning("MITM Simulation ON: Signature corrupted")

                nonce_bytes = bytes.fromhex(req['nonce']) if isinstance(req['nonce'], str) else req['nonce']
                sig_valid = verify_ecdh_pubkey(
                    provider_signing_pub, provider_signature, req['provider_pub_key'], nonce_bytes  
                )

                if not sig_valid:
                    log_security_event(
                        user_id=user_id,
                        event_type="ECDSA_VERIFICATION_FAILED",
                        severity="CRITICAL",
                        request_id=req_id,
                        details="Provider ECDSA signature invalid - possible MITM attack",
                        patient_id=user_id,
                        provider_id=req['provider_id']
                    )
                    st.error("⚠ WARNING: Provider signature invalid - possible MITM attack")
                else:
                    st.success("✅ Provider identity verified via ECDSA signature")

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("✅ Approve Selected Files", key=f"approve_{req_id}",
                                type="primary", disabled=not sig_valid or len(approved_files)==0):
                        # 1. Generate ephemeral ECDH keypair
                        patient_priv, patient_pub = generate_ecdh_keypair()
                        patient_pub_bytes = serialize_public_key(patient_pub)

                        # 2. Sign patient ECDH pubkey
                        patient_signing_priv = st.session_state.signing_keys[user_id]["priv"]
                        nonce_bytes = bytes.fromhex(req['nonce']) if isinstance(req['nonce'], str) else req['nonce']
                        patient_signature = sign_ecdh_pubkey(patient_signing_priv, patient_pub_bytes, nonce_bytes)

                        # 3. Derive shared keys
                        provider_pub = deserialize_public_key(req['provider_pub_key'])
                        aes_key, mac_key, salt = derive_shared_key_enhanced(patient_priv, provider_pub)

                        # 4. Compute key confirmation
                        nonce_bytes = bytes.fromhex(req['nonce']) if isinstance(req['nonce'], str) else req['nonce']
                        transcript = req['provider_pub_key'] + patient_pub_bytes + nonce_bytes
                        key_conf_mac = compute_key_confirmation(mac_key, transcript)

                        if simulate_keyfail:
                            key_conf_mac = os.urandom(32)
                            st.warning("Key Mismatch Simulation ON: MAC corrupted")

                        mac_valid = verify_key_confirmation(mac_key, transcript, key_conf_mac)
                        if not mac_valid:
                            log_security_event(
                                user_id=user_id,
                                event_type="KEY_CONFIRMATION_FAILED",
                                severity="CRITICAL",
                                request_id=req_id,
                                details="HMAC key confirmation mismatch - key derivation error",
                                patient_id=user_id,
                                provider_id=req['provider_id']
                            )
                            st.error("⚠ CRITICAL: Key Confirmation Failed. Aborting.")
                            st.stop()

                        # 5. ENCRYPT ONLY APPROVED FILES
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        placeholders = ','.join(['?' for _ in approved_files])
                        c.execute(f"SELECT file_id, file_name, file_content FROM provider_files WHERE file_id IN ({placeholders})", approved_files)
                        files_to_encrypt = c.fetchall()
                        conn.close()

                        payload = {
                            "patient_id": user_id,
                            "selected_files": [
                                {"file_id": fid, "file_name": fname, "content": fcontent.hex()}
                                for fid, fname, fcontent in files_to_encrypt
                            ]
                        }
                        plaintext = json.dumps(payload)
                        aad = f"{user_id}:{req['provider_id']}:{req_id}:{','.join(approved_files)}"
                        encrypted_data = aes_encrypt_enhanced(aes_key, plaintext, aad)

                        # Measure just the crypto time
                        crypto_start = time.perf_counter()
                        encrypted_data = aes_encrypt_enhanced(aes_key, plaintext, aad)
                        crypto_end = time.perf_counter()
                        crypto_time = crypto_end - crypto_start

                        st.write(f"DEBUG - AAD being stored: {aad}")
                        end_time = time.perf_counter()
                        total_access_time = end_time - req['start_time']

                        update_request(
                            request_id=req_id,
                            status="Approved",
                            selected_files=json.dumps(approved_files),
                            encrypted_payload=encrypted_data,
                            aad_used=aad,
                            patient_pub_key=patient_pub_bytes,
                            patient_signature=patient_signature,
                            key_confirmation_mac=key_conf_mac,
                            salt=salt,
                            signature_verified=1 if sig_valid else 0,
                            key_confirmation_verified=1 if mac_valid else 0,
                            access_time=total_access_time
                        )

                        # PFS: Delete ephemeral keys
                        del patient_priv, mac_key

                         # Log both times separately for thesis
                        log_metrics(user_id, "Total Access Time - End to End", total_access_time, req_id, user_id, req['provider_id'])
                        log_metrics(user_id, "Encryption Only", crypto_time, req_id, user_id, req['provider_id'])
                        
                        st.success(f"✅ Approved! {len(approved_files)} files encrypted with AAD binding")
                        st.info(f"⏱ Total: {total_access_time:.4f}s | Encryption: {crypto_time:.4f}s")
                        st.balloons()
                        time.sleep(1)
                        st.rerun()

                with col2:
                    if st.button("❌ Deny", key=f"deny_{req_id}"):
                        update_request(
                            request_id=req_id,
                            status="Denied",
                            denial_reason="Patient declined access",
                            denied_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        )
                        log_security_event(
                            user_id=user_id,
                            event_type="PATIENT_ACCESS_DENIED",
                            severity="INFO",
                            request_id=req_id,
                            details="Patient exercised right to deny access - HIPAA compliance",
                            patient_id=user_id,
                            provider_id=req['provider_id']
                        )
                        log_metrics(user_id, "Access Denied", 0.0, req_id, user_id, req['provider_id'])
                        st.error("Request denied. Provider access blocked.")
                        st.info("**Audit Log Entry Created:** No PHI disclosed.")
                        time.sleep(1)
                        st.rerun()
    else:
        st.info("No pending access requests")

    st.divider()
    st.subheader("My Health Record")
    my_record = PATIENTS[user_id]
    st.json({k: v for k, v in my_record.items() if k!= 'encrypted_data'})

# ==================== ADMIN PORTAL ====================
elif user_data['role'] == "Admin":
    st.header("⚙ System Administrator Portal")
    st.caption("Performance monitoring and security audit for thesis validation")

    tab1, tab2 = st.tabs(["📊 Performance Metrics", "📋 Security Audit Logs"])

    with tab1:
        st.subheader("System Performance - Two Required Tests")
        st.caption("Data for approval time and encryption/decryption performance")
        
        logs = read_logs()
        if logs:
            df = pd.DataFrame(logs)
            df['access_time_sec'] = pd.to_numeric(df['access_time_sec'])
            
            # Split metrics by type
            total_time_df = df[df['action'] == 'Total Access Time - End to End']
            encryption_df = df[df['action'] == 'Encryption Only']
            decryption_df = df[df['action'] == 'Decryption Time - File Decryption']
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("**Test 1: Approval Time**")
                st.caption("Request → Patient Approves")
                if not total_time_df.empty:
                    avg_total = total_time_df['access_time_sec'].mean()
                    st.metric("Average", f"{avg_total:.4f}s")
                    st.metric("Min", f"{total_time_df['access_time_sec'].min():.4f}s")
                    st.metric("Max", f"{total_time_df['access_time_sec'].max():.4f}s")
                    st.metric("Samples", len(total_time_df))
                else:
                    st.info("No data yet")
            
            with col2:
                st.markdown("**Test 2: Encryption Time**")
                st.caption("AES-256-GCM + AAD")
                if not encryption_df.empty:
                    avg_enc = encryption_df['access_time_sec'].mean()
                    st.metric("Average", f"{avg_enc:.4f}s")
                    st.metric("Min", f"{encryption_df['access_time_sec'].min():.4f}s")
                    st.metric("Max", f"{encryption_df['access_time_sec'].max():.4f}s")
                    st.metric("Samples", len(encryption_df))
                else:
                    st.info("No data yet")
            
            with col3:
                st.markdown("**Test 2: Decryption Time**")
                st.caption("AES-256-GCM Verify")
                if not decryption_df.empty:
                    avg_dec = decryption_df['access_time_sec'].mean()
                    st.metric("Average", f"{avg_dec:.4f}s")
                    st.metric("Min", f"{decryption_df['access_time_sec'].min():.4f}s")
                    st.metric("Max", f"{decryption_df['access_time_sec'].max():.4f}s")
                    st.metric("Samples", len(decryption_df))
                else:
                    st.info("No data yet")
            
            st.divider()
            
            # Combined chart
            if not df.empty:
                st.subheader("Performance Timeline")
                chart_data = df.pivot_table(
                    index='timestamp', 
                    columns='action', 
                    values='access_time_sec',
                    aggfunc='mean'
                )
                st.line_chart(chart_data)
            
            st.divider()
            
            # Full data table
            st.subheader("Raw Performance Data")
            st.dataframe(df, use_container_width=True)
            
            # Export for thesis
            csv = df.to_csv(index=False)
            st.download_button(
                "📥 Download thesis_performance_data.csv",
                csv,
                "thesis_performance_data.csv",
                "text/csv",
                help="Use this CSV to calculate averages for your defense"
            )
            
            # Calculate averages for copy-paste
            if not total_time_df.empty and not encryption_df.empty and not decryption_df.empty:
                st.success(f"""
                **For Your Thesis Paper:**
                
                Test 1 - Average Approval Time: **{total_time_df['access_time_sec'].mean():.4f} seconds** (n={len(total_time_df)})
                
                Test 2 - Average Encryption Time: **{encryption_df['access_time_sec'].mean():.4f} seconds** (n={len(encryption_df)})
                
                Test 2 - Average Decryption Time: **{decryption_df['access_time_sec'].mean():.4f} seconds** (n={len(decryption_df)})
                
                Total Crypto Time: **{(encryption_df['access_time_sec'].mean() + decryption_df['access_time_sec'].mean()):.4f} seconds**
                """)
        else:
            st.warning("No performance data yet. Run at least 10 request→approve→decrypt cycles.")

    with tab2:
        st.subheader("Security Audit Trail - HIPAA Compliance")
        st.caption("Proof that unauthorized access is blocked and all actions are logged")
        
        sec_logs = read_security_logs()
        if sec_logs:
            sec_df = pd.DataFrame(sec_logs)
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Security Events", len(sec_df))
            critical_count = sum(1 for log in sec_logs if log['severity'] == 'CRITICAL')
            col2.metric("Critical Alerts", critical_count)
            denied_count = sum(1 for log in sec_logs if log['event_type'] == 'PATIENT_ACCESS_DENIED')
            col3.metric("Patient Denials", denied_count)
            
            st.dataframe(sec_df, use_container_width=True)
            
            st.download_button(
                "📥 Download security_audit.csv",
                sec_df.to_csv(index=False),
                "security_audit.csv",
                "text/csv"
            )
            
            # Show MITM/Key fail tests
            mitm_tests = sec_df[sec_df['event_type'] == 'ECDSA_VERIFICATION_FAILED']
            keyfail_tests = sec_df[sec_df['event_type'] == 'KEY_CONFIRMATION_FAILED']
            
            if not mitm_tests.empty or not keyfail_tests.empty:
                st.success(f"✅ Security tests passed: {len(mitm_tests)} MITM attacks blocked, {len(keyfail_tests)} key mismatches blocked")
        else:
            st.info("No security events logged yet")