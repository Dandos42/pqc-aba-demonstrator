from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import json
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#********************************Basic info****************************************
#This module simulates the Holder (User's Digital Wallet)
#It acts as a secure local element that stores personal PII and paths to the generated lattice-based credentials (.bin files).
#Securely store personal data and cryptographic credentials (.bin files) locally.
#Encrypted data with protection a user password.
#Make the data accessible only when the user enters the correct unlock password.
#Neither the Issuer nor the Verifier can access this data without the user's explicit authentication.
#**********************************************************************************

router = APIRouter()

# Configuration of persistent storage directories
BASE_DIR = "/home/lac/_build" #work directory in dockerfile
WALLET_DIR = os.path.join(BASE_DIR, "wallets") #Path to an encrypted wallet database
os.makedirs(WALLET_DIR, exist_ok=True)

#Static Salt for Key Derivation
WALLET_SALT = b"2026SulPenzenkaUzivatele**2026!"

#THE WALLET CRYPTOGRAPHIC CORE (Registry Security)

#calculates the filename of the user's encrypted database based on their Master Password using SHA-256
#a simulation environment without central storage of usernames and passwords
def get_wallet_filename(password: str) -> str:
    pwd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    #For example: wallet_db_a1b2c3d4.enc
    return os.path.join(WALLET_DIR, f"wallet_db_{pwd_hash[:16]}.enc")

#The Wallet encrypts the data using the user's own password.
#Derives a 256-bit encryption key from the user password (PBKDF2 algorithm; 480000 iterations)
def derive_wallet_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=WALLET_SALT, iterations=480000
    )
    return kdf.derive(password.encode('utf-8'))

#wallet contents (PII + credential paths) to JSON, encrypts it using AES-256-GCM, and securely persists it to disk
def encrypt_wallet_data(data: dict, password: str):
    filename = get_wallet_filename(password)
    key = derive_wallet_key(password) #deriving a key from a password

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    data_bytes = json.dumps(data).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data_bytes, associated_data=None) # Encrypt + MAC tag

    with open(filename, "wb") as f:
        f.write(nonce + ciphertext)

#Unlocks the wallet by verifying the password and decrypts its contents + integrity check
def decrypt_wallet_data(password: str) -> dict:
    filename = get_wallet_filename(password)

    #File exists check
    if not os.path.exists(filename):
        return {}
    try:
        with open(filename, "rb") as f:
            encrypted_data = f.read()

        # Separate the public nonce from the ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Deriving a key from a given password
        key = derive_wallet_key(password)
        aesgcm = AESGCM(key)

        # Authenticated decryption (Verifies the MAC tag before decrypting)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return json.loads(decrypted_bytes.decode('utf-8'))

    except Exception:
        raise ValueError("Authentication Failed: Incorrect password or compromised wallet integrity!")

#Data in the wallet after successful issuance (payload structure)
class ReceiveCredentialRequest(BaseModel):
    user_id: str # Anonymous identifier linking the PII to the lattice keys
    personal_data: dict # The actual Personally Identifiable Information
    wallet_files: dict #Paths to .bin files containing credentials
    wallet_password: str #User password for database encryption

#Unlocking the wallet using the user's password
class UnlockWalletRequest(BaseModel):
    wallet_password: str

#Endpoint simulating the Wallet receiving new credentials from the Issuer.
#It decrypts the current state, appends the new identity, and re-encrypt.
@router.post("/receive")
async def receive_credentials(request: ReceiveCredentialRequest):
    try:
        current_wallet = decrypt_wallet_data(request.wallet_password) #Open the wallet
    except ValueError: #if the password is false or wallet not exist
        current_wallet = {}

    #Add a new entry - personal data + path
    current_wallet[request.user_id] = {
        "personal_data": request.personal_data,
        "wallet_files": request.wallet_files
    }
    #Re-encrypt the entire wallet using the user password (AES-256-GCM).
    encrypt_wallet_data(current_wallet, request.wallet_password)
    return {"status": "success", "message": "Credentials successfully saved."}

#An endpoint simulating a user opening a wallet app by PIN
#Returns the decrypted content + credentials
@router.post("/unlock")
async def unlock_wallet(request: UnlockWalletRequest):
    try:
        wallet_content = decrypt_wallet_data(request.wallet_password) #decrypt file
        return {"status": "success", "data": wallet_content} # If password and integrity is ok, show contents
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))