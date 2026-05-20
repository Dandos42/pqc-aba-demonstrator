from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import sys

#Import individual logical units (routers).
#module Authority, Wallet, Verifier
from authority import router as authority_router
from wallet import router as wallet_router
from prover import router as prover_router
from verifier import router as verifier_router

# ********************************Basic Information****************************************
# This module acts as the main application coordinator and API gateway.
# It initializes the FastAPI application and configures cross-domain requests for the frontend
#*********************************************************** ***********************

# Initializing the FastAPI main application
app = FastAPI(title="PQC Attribute-based authentication")

# The model for a separate user interface (HTML/JS) could securely communicate with this backend API written in Python for demonstration purposes
# Communication from a local disk to a local server.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], #All domain names are allowed
    allow_credentials=True,
    allow_methods=["*"], # Allows all HTTP methods (GET, POST, OPTIONS, etc.)
    allow_headers=["*"], # Allows all HTTP headers
)

#Definitions of individual endpoints + custom URLs
#ISSUER (Authority): Handles personal data ingestion, execution of the C-kernel for blind signing, and maintains the encrypted audit registry
app.include_router(authority_router, prefix="/authority", tags=["Issuer"])

#WALLET: Simulates a local secure element. Handles AES-256-GCM encryption of personal data and stores the binary lattice credentials.
app.include_router(wallet_router, prefix="/wallet", tags=["Wallet"])

# PROVER: Triggered by the Wallet. Loads private keys into isolated RAM and invokes the C-kernel to generate anonymous ZKPs.
app.include_router(prover_router, prefix="/prover", tags=["Prover"])

#VERIFIER: Receives only anonymous ZKP binary matrices and invokes the C-kernel to mathematically validate them.
app.include_router(verifier_router, prefix="/verifier", tags=["Verifier"])

# Status Check
@app.get("/")
def read_root():
    return {"status": "online", "message": "PQC Attribute based authentication is running"}

#Test Data Generation
# automatically  insert's users credentials in the Wallet
# automatically  insert's data to the form in Issuer page and create predefined test users via a sub-script.
@app.post("/setup-test-users", tags=["Utils"])
def setup_test_users():
    try:
        # sys.executable ensures the script uses the exact same Python interpreter running FastAPI
        subprocess.run([sys.executable, "app/gen_test_users.py"], check=True)
        return {"status": "success", "message": "Test users have been successfully generated!"}

    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": f"Script execution error: {str(e)}"}

    except Exception as e:
        return {"status": "error", "message": f"Critical error: {str(e)}"}