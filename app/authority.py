from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os
import uuid
import shutil
from datetime import datetime
#Cryptographic libraries for data security
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#********************************Basic info****************************************
#This module represents the Trusted Authority (Issuer)
#It acts as a trusted anchor that verifies the user's attributes
#Delegates the actual creation of Post-Quantum Zero-Knowledge credentials to th isolated C-kernel via blind signatures.
#It demonstrates the principle of Data Minimization by maintaining a secure, AES-encrypted  audit log without storing sensitive personal data in the log.
#**********************************************************************************

router = APIRouter()

# Configuration of persistent storage directories
BASE_DIR = "/home/lac/_build" #work directory in dockerfile
WALLET_DIR = os.path.join(BASE_DIR, "wallets") # Temporary holding folder for generated .bin credentials
REGISTRY_FILE = os.path.join(BASE_DIR, "authority_registry.enc") # Encrypted Audit Log
os.makedirs(WALLET_DIR, exist_ok=True)

# Static password and salt for Proof of Concept (PoC) purposes.
AUTHORITY_PASSWORD = b"2026TadyTotoJeHesloUradu**2026!"
AUTHORITY_SALT = b"2026StatickaSulProUrad**2026!"

#THE AUTHORITY CRYPTOGRAPHIC CORE (Registry Security)
# Demonstrates Authenticated Encryption (AES-GCM) for log integrity and confidentiality.
#Derives a 256-bit encryption key from the specified password (PBKDF2 algorithm; 480000 iterations)
def derive_master_key() -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=AUTHORITY_SALT, iterations=480000
    )
    return kdf.derive(AUTHORITY_PASSWORD)


MASTER_KEY = derive_master_key() #The resulting key for encryption and decryption

#Reads and decrypts the authority audit log using AES-256-GCM.
def load_registry() -> list:
    #File exists check
    if not os.path.exists(REGISTRY_FILE):
        return []
    try:
        with open(REGISTRY_FILE, "rb") as f:
            encrypted_data = f.read() #Loads the entire encrypted contents
        nonce = encrypted_data[:12] # The first 12 bytes = the nonce (iv);
        ciphertext = encrypted_data[12:] #the rest is the ciphertext

        # Decrypt and verify the MAC tag simultaneously
        aes_gcm = AESGCM(MASTER_KEY)
        decrypted_bytes = aes_gcm.decrypt(nonce, ciphertext, associated_data=None)

        return json.loads(decrypted_bytes.decode('utf-8'))  #The decrypted bytes are converted back to text
    except Exception as e:
        print(f"Critical Security Failure: Registry tampering or decryption error: {e}")
    return []

#Encrypts a new log entry and appends it to the registry.
#A cryptographically secure random nonce is generated for every write operation
def save_to_registry(log_entry: dict):
    current_db = load_registry() #Decrypting the registry and adding a new entry
    current_db.append(log_entry)
    data_bytes = json.dumps(current_db).encode('utf-8') #re-encryption

    aes_gcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12) #Generate a new 12 bytes random iv

    # Encrypt the data and append the authentication tag
    ciphertext = aes_gcm.encrypt(nonce, data_bytes, associated_data=None) #encryption + MAC

    #The nonce and the ciphertext are written to the file
    with open(REGISTRY_FILE, "wb") as f:
        f.write(nonce + ciphertext)

#The data model for the request that the Authority receives from the user via a form
class IssuanceRequest(BaseModel):
    #Data that the authority does not sign and does not enter into the registry
    first_name: str
    last_name: str
    date_of_birth: str
    id_card_number: str
    email: str
    birth_place: str
    street: str
    zip_code: str
    city: str
    is_adult: int   # ZKP Attribute 1 (Legal Age)
    has_license: int # ZKP Attribute 2 (Driver's License)
    clean_record: int  # ZKP Attribute 3 (Clean Criminal Record)

#the credential issuance process, when the user click on button Sign & Isuse in WebApp
#generate lattice keys and blind signatures
@router.post("/issue")
async def issue_credentials(request: IssuanceRequest):

    # Generate an anonymous identifier for the user session
    user_id = str(uuid.uuid4())[:8]

    # Define absolute paths for the C-kernel to serialize the generated lattice structures
    paths = {
        "is_adult": os.path.join(WALLET_DIR, f"{user_id}_adult.bin"),
        "has_license": os.path.join(WALLET_DIR, f"{user_id}_license.bin"),
        "clean_record": os.path.join(WALLET_DIR, f"{user_id}_record.bin")
    }

    try:
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=0" #Disable memory error detection notifications.
        # Invoke the compiled C-kernel via subprocess.
        # The Python orchestrator blocks and waits for the cryptographic operations to complete.

        result = subprocess.run([ #running the compiled program
            os.path.join(BASE_DIR, "create_credentials"),
            str(request.is_adult), paths["is_adult"], #The arguments pass values (1 or 0)
            str(request.has_license), paths["has_license"],
            str(request.clean_record), paths["clean_record"]
        ], check=True, capture_output=True, text=True, env=env)
        c_output = json.loads(result.stdout.strip()) #Measured times + size after completing the calculations from the C program
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    #backing up the public key specifically for this user session
    user_pk_path = os.path.join(WALLET_DIR, f"{user_id}_public_key.bin")
    shutil.copy(os.path.join(BASE_DIR, "public_key.bin"), user_pk_path)

    #Only the timestamp, anonymous UUID, and the scope of attributes are logged.
    #No PII (names, emails) or the actual attribute values (0 or 1) are stored by the Issuer.
    save_to_registry({
        "credential_id": user_id,
        "issued_at": datetime.now().isoformat(),
        "attributes_signed": ["age", "license", "criminal_record"]
    })
    # completion of the issuance process
    # Return the generated file paths, PII, and cryptographic benchmarks to the frontend
    # forwarded to the Holder's Wallet.
    return {
        "status": "success",
        "user_id": user_id,
        "wallet_files": paths,
        "benchmarks": {
            "time_keygen_ms": c_output.get("time_keygen_ms", 0),
            "time_commit_ms": c_output.get("time_commit_ms", 0),
            "time_sign_ms": c_output.get("time_sign_ms", 0),
            "time_issue_single_ms": c_output.get("time_issue_single_ms", 0),
            "wallet_size_bytes": c_output.get("wallet_size_bytes", 0)
        },
        "personal_data": request.model_dump() #The Authority sends the generated .bin files and the user's data to their wallet
    } #FastAPI will clear the memory.

#Displaying the logs in a web application
@router.get("/audit-logs")
async def get_logs():
    return load_registry()