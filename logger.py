# logger.py - Enhanced logging for HIPAA + ISO 25010 compliance
import csv
import os
from datetime import datetime

LOG_FILE = "metrics.csv"
SECURITY_LOG_FILE = "security_audit.csv"  # NEW: Dedicated security log

def log_metrics(user_id, action, access_time_sec, request_id=None, patient_id=None, provider_id=None):
    """
    Log performance metrics - for ISO 25010 evaluation
    Actions: Request Sent, Access Granted, Access Denied
    """
    file_exists = os.path.isfile(LOG_FILE)
    
    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                'timestamp', 'user_id', 'action', 'access_time_sec', 
                'request_id', 'patient_id', 'provider_id'
            ])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
            user_id, action, f"{access_time_sec:.4f}", 
            request_id, patient_id, provider_id
        ])

def log_security_event(user_id, event_type, severity, request_id, details, patient_id=None, provider_id=None):
    """
    NEW: Log security events - for HIPAA audit trail
    event_type: ECDSA_VERIFICATION_FAILED, KEY_CONFIRMATION_FAILED, MITM_DETECTED, etc.
    severity: CRITICAL, HIGH, MEDIUM, INFO
    """
    file_exists = os.path.isfile(SECURITY_LOG_FILE)
    
    with open(SECURITY_LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow([
                'timestamp', 'user_id', 'event_type', 'severity', 
                'request_id', 'details', 'patient_id', 'provider_id'
            ])
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            user_id, event_type, severity,
            request_id, details, patient_id, provider_id
        ])

def read_logs():
    """Read performance logs"""
    if not os.path.isfile(LOG_FILE):
        return []
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

def read_security_logs():
    """NEW: Read security audit logs"""
    if not os.path.isfile(SECURITY_LOG_FILE):
        return []
    with open(SECURITY_LOG_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)