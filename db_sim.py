# db_sim.py - Simulated database with role-based user IDs + passwords

# --- USERS BY ROLE ---
# Format: user_id: {name, role, username, password, specialty/unit}

USERS = {
    # Healthcare Providers
    "HP001_DR_GARCIA": {
        "name": "Dr. Maria Garcia",
        "role": "Healthcare Provider",
        "username": "dr.garcia",
        "password": "Cardio2026!", # Demo only - not secure
        "specialty": "Cardiology",
        "hospital": "St. Luke's Medical Center"
    },
    "HP002_DR_REYES": {
        "name": "Dr. John Reyes",
        "role": "Healthcare Provider",
        "username": "dr.reyes",
        "password": "Internal2026!",
        "specialty": "Internal Medicine",
        "hospital": "Philippine General Hospital"
    },

    # Patients
    "PT001_M_SANTOS": {
        "name": "Maria Santos",
        "role": "Patient",
        "username": "maria.santos",
        "password": "Patient123!",
        "age": 45,
        "record_id": "MR-2024-001"
    },
    "PT002_J_DELA_CRUZ": {
        "name": "Juan Dela Cruz",
        "role": "Patient",
        "username": "juan.delacruz",
        "password": "Patient123!",
        "age": 52,
        "record_id": "MR-2024-002"
    },
    "PT003_A_LIM": {
        "name": "Ana Lim",
        "role": "Patient",
        "username": "ana.lim",
        "password": "Patient123!",
        "age": 38,
        "record_id": "MR-2024-003"
    },

    # System Administrators / IT Experts
    "AD001_ADMIN": {
        "name": "System Administrator",
        "role": "Admin",
        "username": "admin",
        "password": "Admin2026!",
        "department": "IT Security"
    },
    "AD002_IT_EXPERT": {
        "name": "IT Security Expert",
        "role": "Admin",
        "username": "it.expert",
        "password": "Expert2026!",
        "department": "Cybersecurity Unit"
    }
}

# --- PATIENT RECORDS (encrypted data simulated) ---
PATIENTS = {
    "PT001_M_SANTOS": {
        "name": "Maria Santos",
        "dob": "1979-03-15",
        "blood_type": "O+",
        "allergies": "Penicillin",
        "diagnosis": "Hypertension",
        "last_visit": "2026-03-10",
        "encrypted_data": b"SIMULATED_ENCRYPTED_PAYLOAD_MARIA"
    },
    "PT002_J_DELA_CRUZ": {
        "name": "Juan Dela Cruz",
        "dob": "1974-07-22",
        "blood_type": "A+",
        "allergies": "None",
        "diagnosis": "Type 2 Diabetes",
        "last_visit": "2026-02-28",
        "encrypted_data": b"SIMULATED_ENCRYPTED_PAYLOAD_JUAN"
    },
    "PT003_A_LIM": {
        "name": "Ana Lim",
        "dob": "1988-11-05",
        "blood_type": "B+",
        "allergies": "Shellfish",
        "diagnosis": "Asthma",
        "last_visit": "2026-04-01",
        "encrypted_data": b"SIMULATED_ENCRYPTED_PAYLOAD_ANA"
    }
}

# --- ACCESS REQUESTS (populated at runtime) ---
REQUESTS = {}

# --- HELPER FUNCTIONS ---
def get_user_by_id(user_id):
    """Return user info dict or None"""
    return USERS.get(user_id)

def get_user_by_username(username):
    """Return user_id and user_data tuple or None"""
    for uid, data in USERS.items():
        if data["username"] == username:
            return uid, data
    return None, None

def get_users_by_role(role):
    """Return dict of users filtered by role"""
    return {uid: data for uid, data in USERS.items() if data["role"] == role}

def get_patient_record(patient_id):
    """Return patient medical record or None"""
    return PATIENTS.get(patient_id)

def authenticate(username, password):
    """Check username/password and return user_id, user_data if valid"""
    uid, user_data = get_user_by_username(username)
    if user_data and user_data["password"] == password:
        return uid, user_data
    return None, None