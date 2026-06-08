# db_sim.py - SQLite backend with auto-seed
import sqlite3
import os
from datetime import datetime
import time

DB_PATH = "shies.db"

# --- In-memory dicts for fast login lookup ---
USERS = {
    "HP001_DR_GARCIA": {"id": "HP001_DR_GARCIA", "name": "Dr. Maria Garcia", "role": "Healthcare Provider", "password": "Cardio2026!", "specialty": "Cardiology", "hospital": "Manila General Hospital", "department": "IT"},
    "PT001_M_SANTOS": {"id": "PT001_M_SANTOS", "name": "Maria Santos", "role": "Patient", "password": "Patient123!", "record_id": "REC-001"},
    "ADMIN": {"id": "ADMIN", "name": "System Admin", "role": "Admin", "password": "Admin2026!", "department": "IT"}
}

PATIENTS = {
    "PT001_M_SANTOS": {"id": "PT001_M_SANTOS", "name": "Maria Santos", "dob": "1979-03-15", "blood_type": "O+", "allergies": "Penicillin", "diagnosis": "Hypertension"}
}

REQUESTS = {} # Legacy - not used but prevents import error

def init_db():
    """Initialize database tables and seed with default users/patients"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, name TEXT, role TEXT, password TEXT, specialty TEXT, hospital TEXT, department TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS patients (
        id TEXT PRIMARY KEY, name TEXT, dob TEXT, blood_type TEXT, allergies TEXT, diagnosis TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS provider_files (
        file_id TEXT PRIMARY KEY,
        provider_id TEXT,
        patient_id TEXT,
        file_name TEXT,
        file_type TEXT,
        file_description TEXT,
        file_content BLOB,
        file_size INTEGER,
        uploaded_at TEXT
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS access_requests (
        request_id TEXT PRIMARY KEY,
        provider_id TEXT,
        patient_id TEXT,
        status TEXT,
        timestamp TEXT,
        provider_pub_key BLOB,
        provider_signature BLOB,
        nonce TEXT,
        selected_files TEXT,
        encrypted_payload BLOB,
        aad_used TEXT, 
        patient_pub_key BLOB,
        patient_signature BLOB,
        key_confirmation_mac BLOB,
        salt BLOB,
        signature_verified INTEGER,
        key_confirmation_verified INTEGER,
        denial_reason TEXT,
        denied_at TEXT,
        security_alerts TEXT,
        access_time REAL,
        start_time REAL
        )''')

    c.execute('CREATE INDEX IF NOT EXISTS idx_provider_files_patient ON provider_files(patient_id, provider_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_requests_patient ON access_requests(patient_id, status)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_requests_provider ON access_requests(provider_id)')
    # SEED USERS - Insert if not exists
    for uid, udata in USERS.items():
        c.execute('''INSERT OR IGNORE INTO users (id, name, role, password, specialty, hospital, department)
                     VALUES (?,?,?,?,?,?,?)''',
                  (uid, udata['name'], udata['role'], udata['password'],
                   udata.get('specialty'), udata.get('hospital'), udata.get('department')))

    # SEED PATIENTS - Insert if not exists
    for pid, pdata in PATIENTS.items():
        c.execute('''INSERT OR IGNORE INTO patients (id, name, dob, blood_type, allergies, diagnosis)
                     VALUES (?,?,?,?,?,?)''',
                  (pid, pdata['name'], pdata['dob'], pdata['blood_type'], pdata['allergies'], pdata['diagnosis']))

    conn.commit()
    conn.close()

def add_provider_file(file_id, provider_id, patient_id, file_name, file_type, description, file_content):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO provider_files
                 (file_id, provider_id, patient_id, file_name, file_type, file_description, file_content, file_size, uploaded_at)
                 VALUES (?,?,?,?,?,?,?,?,?)''',
              (file_id, provider_id, patient_id, file_name, file_type, description, file_content, len(file_content),
               datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_patient_files(patient_id, provider_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT file_id, file_name, file_type, file_description, file_size, uploaded_at
                 FROM provider_files
                 WHERE patient_id =? AND provider_id =?''', (patient_id, provider_id))
    files = c.fetchall()
    conn.close()
    return files

def get_file_content(file_id):
    """Get actual file bytes for decryption"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT file_name, file_content FROM provider_files WHERE file_id =?", (file_id,))
    row = c.fetchone()
    conn.close()
    return row if row else (None, None)

def create_request(request_id, provider_id, patient_id, provider_pub_key, provider_signature, nonce):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO access_requests
                 (request_id, provider_id, patient_id, status, timestamp, provider_pub_key, provider_signature, nonce, security_alerts, start_time)
                 VALUES (?,?,?,'Pending',?,?,?,?, '[]',?)''',
              (request_id, provider_id, patient_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               provider_pub_key, provider_signature, nonce, time.perf_counter()))
    conn.commit()
    conn.close()

def update_request(request_id, **kwargs):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    set_clause = ', '.join([f"{k} =?" for k in kwargs.keys()])
    values = list(kwargs.values()) + [request_id]
    c.execute(f"UPDATE access_requests SET {set_clause} WHERE request_id =?", values)
    conn.commit()
    conn.close()

def get_request(request_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM access_requests WHERE request_id =?", (request_id,))
    row = c.fetchone()
    columns = [description[0] for description in c.description]
    conn.close()
    return dict(zip(columns, row)) if row else None

def get_patient_requests(patient_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM access_requests WHERE patient_id =? AND status = 'Pending'", (patient_id,))
    rows = c.fetchall()
    columns = [description[0] for description in c.description]
    conn.close()
    return [dict(zip(columns, row)) for row in rows]

def get_provider_requests(provider_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM access_requests WHERE provider_id =?", (provider_id,))
    rows = c.fetchall()
    columns = [description[0] for description in c.description]
    conn.close()
    return [dict(zip(columns, row)) for row in rows]

def get_user_by_id(uid):
    return USERS.get(uid)

def authenticate(username, password):
    for uid, udata in USERS.items():
        if udata['id'] == username and udata['password'] == password:
            return uid, udata
    return None, None



# Initialize DB and seed on import
init_db()