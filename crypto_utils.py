# crypto_utils.py - Enhanced AES-256-GCM + ECDH-P256 + ECDSA + Key Confirmation
import os
import secrets  # ADDED: Missing import
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.exceptions import InvalidSignature, InvalidTag

# --- ECDH: Ephemeral Key Exchange ---
def generate_ecdh_keypair():
    """Generate ephemeral ECDH P-256 keypair for key exchange"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key) -> bytes:
    """Serialize public key to bytes for transmission"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes: bytes):
    """Deserialize bytes back to public key object"""
    return serialization.load_pem_public_key(public_key_bytes)

def derive_shared_key_enhanced(priv_key, peer_pub_key, salt=None, info=b"HIE-Patient-Provider-v1"):
    """
    Enhanced: Derive AES-256 + MAC-256 keys via ECDH + HKDF
    Returns: (aes_key, mac_key, salt) for key confirmation
    """
    shared_secret = priv_key.exchange(ec.ECDH(), peer_pub_key)

    if salt is None:
        salt = os.urandom(16)

    # Derive 64 bytes: 32 for AES, 32 for MAC confirmation
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=info,
    )
    key_material = hkdf.derive(shared_secret)
    aes_key = key_material[:32]
    mac_key = key_material[32:]

    return aes_key, mac_key, salt

# --- Key Confirmation ---
def compute_key_confirmation(mac_key: bytes, transcript: bytes) -> bytes:
    """Compute HMAC over handshake transcript to confirm both parties have same key"""
    h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
    h.update(transcript)
    return h.finalize()

def verify_key_confirmation(mac_key: bytes, transcript: bytes, received_mac: bytes) -> bool:
    """Verify key confirmation MAC. Returns False if keys don't match."""
    try:
        h = crypto_hmac.HMAC(mac_key, hashes.SHA256())
        h.update(transcript)
        h.verify(received_mac)
        return True
    except:
        return False

# --- ECDSA: Mutual Authentication ---
def generate_signing_keypair():
    """Generate long-term identity keypair for digital signatures"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def sign_ecdh_pubkey(signing_priv_key, ecdh_pubkey_bytes: bytes, nonce: bytes) -> bytes:
    """Sign ephemeral ECDH pubkey + nonce to prove ownership + prevent replay"""
    message = ecdh_pubkey_bytes + nonce
    return signing_priv_key.sign(message, ec.ECDSA(hashes.SHA256()))

def verify_ecdh_pubkey(signing_pub_key, signature: bytes, ecdh_pubkey_bytes: bytes, nonce: bytes) -> bool:
    """Verify signature on ECDH pubkey. Returns False if MITM tampered."""
    try:
        message = ecdh_pubkey_bytes + nonce
        signing_pub_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# --- AES-256-GCM with AAD Binding ---
def aes_encrypt_enhanced(aes_key, plaintext, aad):
    """
    AES-256-GCM with Associated Authenticated Data (AAD)
    AAD binds ciphertext to context - prevents replay attacks
    """
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
    if isinstance(aad, str):
        aad = aad.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext

def aes_decrypt_enhanced(aes_key, encrypted_data, aad):
    """
    AES-256-GCM decryption with AAD verification
    Raises exception if AAD doesn't match - detects tampering
    """
    aesgcm = AESGCM(aes_key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    if isinstance(aad, str):
        aad = aad.encode('utf-8')
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
        return plaintext_bytes.decode('utf-8')
    except InvalidTag:
        raise ValueError("Decryption failed: Invalid AAD or tampered ciphertext - possible attack")

# --- Legacy functions ---
def derive_shared_key(priv_key, peer_pub_key, salt=None, info=b"HIE-Patient-Provider-v1"):
    """Legacy: Use derive_shared_key_enhanced instead"""
    aes_key, _, _ = derive_shared_key_enhanced(priv_key, peer_pub_key, salt, info)
    return aes_key