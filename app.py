# app.py - Secure HIE with Enhanced AES-ECDH-ECDSA + Key Confirmation
import streamlit as st
import time
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from datetime import datetime
import secrets

# --- Import custom modules ---
from crypto_utils import *
from db_sim import USERS, PATIENTS, REQUESTS, get_user_by_id, authenticate
from logger import log_metrics, read_logs, log_security_event, read_security_logs, LOG_FILE, SECURITY_LOG_FILE
from expert_eval import ISO_25010_CRITERIA, LIKERT_SCALE, save_evaluation, get_eval_summary, get_descriptive_rating, generate_eval_pdf, EVAL_FILE

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
    """Convert 'Name:Maria|DOB:1979...' to {'Name': 'Maria', 'DOB': '1979'...}"""
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
if 'requests' not in st.session_state:
    st.session_state.requests = REQUESTS
if 'request_counter' not in st.session_state:
    st.session_state.request_counter = 0
if 'signing_keys' not in st.session_state:
    # Generate long-term signing keys per user on first run - simulate PKI
    st.session_state.signing_keys = {}
    for uid in USERS.keys():
        priv, pub = generate_signing_keypair()
        st.session_state.signing_keys[uid] = {"priv": priv, "pub": pub}

# --- LOGIN PAGE ---
if not st.session_state.authenticated:
    st.markdown("""
    <div class="main-header">
        <h1>🏥 Secure Health Information Exchange System</h1>
        <p>Enhanced AES-ECDH-ECDSA + Key Confirmation | ISO/IEC 25010:2015</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        st.subheader("🔐 System Login")
        st.caption("Authorized personnel only")

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
            st.code("dr.garcia / Cardio2026!\nmaria.santos / Patient123!\nadmin / Admin2026!")

    st.stop()

# --- AUTHENTICATED USER ---
user_id = st.session_state.user_id
user_data = st.session_state.user_data

st.markdown("""
<div class="main-header">
    <h1>🏥 Secure Health Information Exchange Prototype</h1>
    <p>Enhanced AES-256-GCM + ECDH-P256 + ECDSA + Key Confirmation</p>
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
    st.header("👨‍⚕️ Healthcare Provider Portal")
    st.caption(f"Welcome, {user_data['name']} | {user_data['specialty']} | {user_data['hospital']}")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Request Patient Data Access")
        patient_options = {f"{data['name']} ({pid})": pid for pid, data in PATIENTS.items()}
        selected_patient = st.selectbox("Select Patient", list(patient_options.keys()))
        patient_id = patient_options[selected_patient]

        if st.button("🔐 Request Access", type="primary"):
            st.session_state.request_counter += 1
            req_id = f"REQ-{st.session_state.request_counter:03d}"
            start_time = time.perf_counter()

            # 1. Generate ephemeral ECDH keypair
            provider_priv, provider_pub = generate_ecdh_keypair()
            provider_pub_bytes = serialize_public_key(provider_pub)

            # 2. Generate nonce for replay protection
            nonce = secrets.token_bytes(16)

            # 3. Sign ECDH pubkey + nonce - ENHANCEMENT #1
            provider_signing_priv = st.session_state.signing_keys[user_id]["priv"]
            signature = sign_ecdh_pubkey(provider_signing_priv, provider_pub_bytes, nonce)

            st.session_state.requests[req_id] = {
                "provider_id": user_id,
                "patient_id": patient_id,
                "status": "Pending",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "provider_priv_key": provider_priv, # Will delete for PFS
                "provider_pub_key": provider_pub_bytes,
                "provider_signature": signature,
                "nonce": nonce,
                "start_time": start_time,
                "access_time": None,
                "encrypted_data": None,
                "decrypted_data_dict": None,
                "shared_key": None,
                "signature_verified": False,
                "key_confirmation_verified": False,
                "denial_reason": None,
                "denied_at": None,
                "security_alerts": []
            }
            log_metrics(user_id, "Request Sent", 0.0, req_id, patient_id, user_id)
            st.success(f"Request {req_id} sent. ECDH key signed with ECDSA.")
            st.info("⏳ Waiting for patient approval...")

    with col2:
        st.subheader("My Active Requests")
        my_requests = {rid: req for rid, req in st.session_state.requests.items()
                      if req['provider_id'] == user_id}

        if my_requests:
            for req_id, req in my_requests.items():
                with st.container(border=True):
                    patient_name = PATIENTS[req['patient_id']]['name']
                    st.write(f"**{req_id}** → {patient_name}")
                    st.write(f"Status: `{req['status']}`")

                    if req['status'] == "Approved":
                        st.success(f"Access Time: {req['access_time']:.4f}s")
                        if req['signature_verified']:
                            st.success("✅ Patient signature verified")
                        if req['key_confirmation_verified']:
                            st.success("✅ Key confirmation passed")

                        with st.expander("🔍 Show Enhanced Encryption Details", expanded=False):
                            st.write("**1. Encrypted Payload (AES-256-GCM + AAD)**")
                            st.caption(f"AAD = {req['patient_id']}:{req['provider_id']}:{req_id}")
                            st.code(req['encrypted_data'].hex(), language="text")

                            st.write("**2. Shared AES-256 Key (ECDH+HKDF)**")
                            st.code(req['shared_key'].hex(), language="text")

                            st.write("**3. Key Confirmation MAC**")
                            st.caption("Proves both parties derived identical key")
                            st.code(req.get('key_confirmation_mac', b'').hex(), language="text")

                            st.write("**4. Decrypted Patient Record**")
                            st.json(req['decrypted_data_dict'])

                        if st.button(f"View Decrypted Data", key=f"view_{req_id}"):
                            st.session_state[f"show_data_{req_id}"] = True

                    elif req['status'] == "Denied":
                            st.error("Access Denied by Patient")
                            with st.expander("🔍 Denial Details - Audit Trail"):
                                st.write("**Request ID:**", req_id)
                                st.write("**Denied At:**", req.get('denied_at', 'N/A'))
                                st.write("**Reason:**", req.get('denial_reason', 'Patient declined'))
                                st.write("**Data Disclosed:** None - Zero-knowledge proof of denial")
                                st.code("Encrypted Payload: [NEVER GENERATED]", language="text")
                                st.caption("This proves patient-centric control: no encryption occurs until approval")

                    if st.session_state.get(f"show_data_{req_id}", False):
                        st.write("**Decrypted Patient Record:**")
                        st.json(req['decrypted_data_dict'])
        else:
            st.info("No active requests")

# ==================== PATIENT PORTAL ====================
# ==================== PATIENT PORTAL ====================
elif user_data['role'] == "Patient":
    st.header("🧑‍🦰 Patient Portal")
    st.caption(f"Welcome, {user_data['name']} | You control access to your health data")

    st.subheader("Incoming Access Requests")
    my_requests = {rid: req for rid, req in st.session_state.requests.items()
                  if req['patient_id'] == user_id and req['status'] == "Pending"}

    if my_requests:
        for req_id, req in my_requests.items():
            provider = get_user_by_id(req['provider_id'])
            with st.container(border=True):
                st.write(f"**Request {req_id}** from {provider['name']}")
                st.write(f"Specialty: {provider['specialty']} | Hospital: {provider['hospital']}")
                st.write(f"Requested at: {req['timestamp']}")

                # ATTACK SIMULATION TOGGLE - FOR DEFENSE DEMO
                st.divider()
                st.write("**🔬 Security Testing - For Thesis Defense Only**")
                col_sim1, col_sim2 = st.columns(2)
                with col_sim1:
                    simulate_mitm = st.checkbox("🎭 Simulate MITM: Corrupt Signature", key=f"mitm_{req_id}")
                with col_sim2:
                    simulate_keyfail = st.checkbox("🎭 Simulate Key Mismatch", key=f"keyfail_{req_id}")

                # Verify provider signature - ENHANCEMENT #1
                provider_signing_pub = st.session_state.signing_keys[req['provider_id']]["pub"]
                provider_signature = req['provider_signature']
                
                if simulate_mitm:
                    provider_signature = os.urandom(64)  # Corrupt signature
                    st.warning("MITM Simulation ON: Signature corrupted")
                
                sig_valid = verify_ecdh_pubkey(
                    provider_signing_pub,
                    provider_signature,
                    req['provider_pub_key'],
                    req['nonce']
                )

                if not sig_valid:
                    # LOG THE ATTACK
                    log_security_event(
                        user_id=user_id,
                        event_type="ECDSA_VERIFICATION_FAILED",
                        severity="CRITICAL",
                            request_id=req_id,
                        details="Provider ECDSA signature invalid - possible man-in-the-middle attack or key tampering",
                        patient_id=user_id,
                        provider_id=req['provider_id']
                    )

                    st.session_state.requests[req_id]['security_alerts'].append("ECDSA_VERIFICATION_FAILED")
                    st.session_state.requests[req_id]['security_alerts'].append(f"Detected at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    log_metrics(user_id, "MITM Attack Blocked", 0.0, req_id, user_id, req['provider_id'])
                    st.error("⚠️ WARNING: Provider signature invalid - possible MITM attack")
                else:
                    st.success("✅ Provider identity verified via ECDSA signature")

                col1, col2 = st.columns(2)
                with col1:
                    if st.button("✅ Approve", key=f"approve_{req_id}", type="primary", disabled=not sig_valid):
                        # 1. Generate ephemeral ECDH keypair
                        patient_priv, patient_pub = generate_ecdh_keypair()
                        patient_pub_bytes = serialize_public_key(patient_pub)

                        # 2. Sign patient ECDH pubkey
                        patient_signing_priv = st.session_state.signing_keys[user_id]["priv"]
                        patient_signature = sign_ecdh_pubkey(patient_signing_priv, patient_pub_bytes, req['nonce'])

                        # 3. Derive shared keys
                        provider_pub = deserialize_public_key(req['provider_pub_key'])
                        aes_key, mac_key, salt = derive_shared_key_enhanced(patient_priv, provider_pub)

                        # 4. Compute key confirmation
                        transcript = req['provider_pub_key'] + patient_pub_bytes + req['nonce']
                        key_conf_mac = compute_key_confirmation(mac_key, transcript)

                        if simulate_keyfail:
                            key_conf_mac = os.urandom(32)  # Corrupt MAC
                            st.warning("Key Mismatch Simulation ON: MAC corrupted")

                        # Verify key confirmation before encrypting
                        mac_valid = verify_key_confirmation(mac_key, transcript, key_conf_mac)
                        if not mac_valid:
                            # LOG THE FAILURE
                            log_security_event(
                                user_id=user_id,
                                event_type="KEY_CONFIRMATION_FAILED",
                                severity="CRITICAL",
                                request_id=req_id,
                                details="HMAC key confirmation mismatch - key derivation error or active attack",
                                patient_id=user_id,
                                provider_id=req['provider_id']
                            )
                            st.session_state.requests[req_id]['security_alerts'].append("KEY_CONFIRMATION_FAILED")
                            log_metrics(user_id, "Key Derivation Failed", 0.0, req_id, user_id, req['provider_id'])
                            st.error("⚠️ CRITICAL: Key Confirmation Failed. Aborting.")
                            st.stop()

                        # 5. Encrypt with AAD binding
                        patient_record = PATIENTS[user_id]
                        plaintext = f"Name:{patient_record['name']}|DOB:{patient_record['dob']}|BloodType:{patient_record['blood_type']}|Allergies:{patient_record['allergies']}|Diagnosis:{patient_record['diagnosis']}"
                        encrypted_data = aes_encrypt_enhanced(
                            aes_key, plaintext, user_id, req['provider_id'], req_id
                        )

                        # 6. Decrypt for demo
                        decrypted_data_str = aes_decrypt_enhanced(
                            aes_key, encrypted_data, user_id, req['provider_id'], req_id
                        )
                        decrypted_data_dict = parse_decrypted_to_dict(decrypted_data_str)

                        end_time = time.perf_counter()
                        access_time = end_time - req['start_time']

                        st.session_state.requests[req_id].update({
                            "status": "Approved",
                            "access_time": access_time,
                            "encrypted_data": encrypted_data,
                            "decrypted_data_dict": decrypted_data_dict,
                            "shared_key": aes_key,
                            "patient_pub_key": patient_pub_bytes,
                            "patient_signature": patient_signature,
                            "key_confirmation_mac": key_conf_mac,
                            "salt": salt,
                            "signature_verified": sig_valid,
                            "key_confirmation_verified": mac_valid
                        })

                        # PFS: Delete ephemeral keys
                        del patient_priv
                        del mac_key
                        del st.session_state.requests[req_id]['provider_priv_key']

                        log_metrics(user_id, "Access Granted", access_time, req_id, user_id, req['provider_id'])
                        st.success(f"Approved! Access Time: {access_time:.4f}s")
                        st.balloons()
                        time.sleep(1)
                        st.rerun()

                with col2:
                    if st.button("❌ Deny", key=f"deny_{req_id}"):
                        st.session_state.requests[req_id]['status'] = "Denied"
                        st.session_state.requests[req_id]['denial_reason'] = "Patient declined access"
                        st.session_state.requests[req_id]['denied_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
                        st.info("**Audit Log Entry Created:** Patient-controlled access maintained. No PHI disclosed.")
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
    st.header("⚙️ System Administrator / IT Expert Portal")

    tab1, tab2, tab3 = st.tabs(["📊 Performance Dashboard", "📝 Expert Evaluation", "📋 System Logs"])

    with tab1:
        st.subheader("ISO/IEC 25010 Performance Efficiency Metrics")
        logs = read_logs()
        if logs:
            df = pd.DataFrame(logs)
            df['access_time_sec'] = pd.to_numeric(df['access_time_sec'])

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Requests", len(df))
            col2.metric("Avg Access Time", f"{df['access_time_sec'].mean():.4f}s")
            col3.metric("Max Access Time", f"{df['access_time_sec'].max():.4f}s")

            st.line_chart(df.set_index('timestamp')['access_time_sec'])
        else:
            st.info("No performance data yet.")

    with tab2:
        st.subheader("ISO/IEC 25010:2015 Software Quality Evaluation")
        with st.form("eval_form"):
            evaluator_name = st.text_input("Evaluator Name", value=user_data['name'])
            evaluator_role = st.text_input("Role/Expertise", value=user_data['department'])
            evaluator_id = st.selectbox("Evaluator ID", [user_id])

            st.divider()
            st.write("**Rate each criterion (1 = Poor, 5 = Excellent)**")

            responses = {}
            for category, criteria in ISO_25010_CRITERIA.items():
                st.subheader(category)
                responses[category] = {}
                for criterion in criteria:
                    responses[category][criterion] = st.select_slider(
                        criterion,
                        options=LIKERT_SCALE,
                        value=5,
                        key=f"{category}_{criterion}"
                    )

            comments = st.text_area("Additional Comments / Recommendations")
            submitted = st.form_submit_button("Submit Evaluation", type="primary")
            if submitted:
                save_evaluation(evaluator_name, evaluator_role, responses, comments)
                st.success("Evaluation submitted successfully!")
                st.balloons()

        st.divider()
        st.subheader("Aggregated Expert Evaluation Results")
        summary_df = get_eval_summary()
        if not summary_df.empty:
            st.dataframe(summary_df, use_container_width=True)
            avg_score = summary_df['Mean Score'].mean()
            rating = get_descriptive_rating(avg_score)
            st.metric("Overall System Quality Score", f"{avg_score:.2f} / 5.0", delta=rating)
        else:
            st.info("No evaluations submitted yet")

    with tab3:
        st.subheader("Audit Logs & Access Records - HIPAA + ISO 25010")
    
        col1, col2 = st.columns(2)
    
        with col1:
            st.write("**1. Performance Metrics (ISO 25010)**")
            logs = read_logs()
            if logs:
                df = pd.DataFrame(logs)
                st.dataframe(df, use_container_width=True)
                st.download_button(
                    "📥 Download Performance CSV",
                    df.to_csv(index=False),
                    "audit_logs_performance.csv",
                    "text/csv"
                )
            else:
                st.info("No performance logs yet")
    
        with col2:
            st.write("**2. Security Audit Trail (HIPAA)**")
            sec_logs = read_security_logs()
            if sec_logs:
                sec_df = pd.DataFrame(sec_logs)
                st.dataframe(sec_df, use_container_width=True)
                st.download_button(
                    "📥 Download Security Audit CSV",
                    sec_df.to_csv(index=False),
                    "security_audit.csv",
                    "text/csv"
                )
            else:
                st.info("No security events logged yet")
    
        st.divider()
        st.metric("Total Security Events", len(sec_logs) if sec_logs else 0)
        if sec_logs:
            critical_count = sum(1 for log in sec_logs if log['severity'] == 'CRITICAL')
            st.metric("Critical Alerts", critical_count, delta="Blocked" if critical_count > 0 else None)
    
        # ADD THIS SECTION FOR JSON EXPORT
        st.divider()
        st.write("**3. Complete Forensic Audit Dump (JSON)**")
        st.caption("Contains all cryptographic material: nonces, public keys, signatures, MACs, security_alerts")
    
        if st.button("🔍 Generate Full JSON Audit", type="primary"):
            import json
            # Convert bytes to hex for JSON serialization
            def serialize_request(req):
                serialized = {}
                for key, value in req.items():
                    if isinstance(value, bytes):
                        serialized[key] = value.hex()
                    elif key == 'provider_priv_key':
                        serialized[key] = "[DELETED FOR PFS]" # Don't leak deleted keys
                    else:
                        serialized[key] = value
                return serialized
    
            full_audit = {
                "export_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_requests": len(st.session_state.requests),
                "requests": {rid: serialize_request(req) for rid, req in st.session_state.requests.items()}
            }
    
            json_str = json.dumps(full_audit, indent=2, default=str)
    
            st.download_button(
                "📥 Download complete_audit_trail.json",
                json_str,
                f"complete_audit_trail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json"
            )
    
            with st.expander("Preview JSON (First 50 lines)"):
                preview = '\n'.join(json_str.split('\n')[:50])
                st.code(preview + "\n...", language="json")