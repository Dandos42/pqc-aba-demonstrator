from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os
import uuid
import shutil

# ********************************Basic info****************************************
# This module simulates the Prover
# It handles the Zero-Knowledge Proof (ZKP) generation process by securely invoking isolated C binaries (Prover).
# **********************************************************************************

router = APIRouter()

# Setup working directories for Docker integration
BASE_DIR = "/home/lac/_build"
PROVER_EXE = os.path.join(BASE_DIR, "generate_proof")

#Data model for the ZKP generation request.
class ProofRequest(BaseModel):
    user_id: str
    scenario: str
    wallet_file_path: str

#Triggers the C-kernel to generate an anonymous Zero-Knowledge Proof
@router.post("/generate-proof")
async def generate_proof(request: ProofRequest):
    # Map real-world scenarios to required mathematical attribute values
    scenarios = {
        "alcohol": {"val": "1", "msg": "Age Verification (Threshold > 18)"},
        "police": {"val": "1", "msg": "Police Check (Driving License)"},
        "hr": {"val": "1", "msg": "Criminal records (Clean Criminal Record)"}
    }

    # Validate the requested scenario
    if request.scenario not in scenarios:
        raise HTTPException(status_code=400, detail="Unknown verification scenario.")

    config = scenarios[request.scenario]

    # Check if the wallet file exists on the disk
    # Ensure the user's wallet file exists locally
    if not os.path.exists(request.wallet_file_path):
        raise HTTPException(status_code=404, detail="The authorization file was not found.")

    # Copy the environment variables from the operating system
    env_vars = os.environ.copy()
    env_vars["ASAN_OPTIONS"] = "detect_leaks=0"  # Disable memory error detection notifications.

    # Generate a unique temporary file path for the resulting ZKP
    proof_file_path = os.path.join(BASE_DIR, f"zkp_proof_{uuid.uuid4().hex}.bin")

    # Load the correct Authority Public Key specific to this user
    WALLET_DIR = os.path.join(BASE_DIR, "wallets")
    user_pk_path = os.path.join(WALLET_DIR, f"{request.user_id}_public_key.bin")
    target_pk_path = os.path.join(BASE_DIR, "public_key.bin")

    # If a backup exists, we'll use it to overwrite the main file, public_key.bin
    if os.path.exists(user_pk_path):
        shutil.copy(user_pk_path, target_pk_path)

    try:
        # Execute the compiled C-kernel.
        # Note: 'check=True' is intentionally omitted to safely catch local rejections.
        prover_result = subprocess.run(
            [PROVER_EXE, config["val"], request.wallet_file_path, proof_file_path],
            capture_output=True, text=True, env=env_vars
        )

        # Parse the JSON output from the C-kernel
        try:
            prover_output = json.loads(prover_result.stdout.strip())
        except json.JSONDecodeError:
            return {"status": "error", "message": "Prover output error.", "details": prover_result.stderr}

        #Handle local rejection (user does not possess the required attribute)
        if prover_output.get("status") == "error":
            return {
                "status": "unauthorized",
                "message": prover_output.get("message", "Error generating proof"),
                "scenario_msg": config["msg"]
            }

        # Extract hardware execution benchmarks
        prover_details = {
            "time_prove_ms": prover_output.get("time_prove_ms", 0.0),
            "time_embed_ms": prover_output.get("time_embed_ms", 0.0),
            "time_prove_fs_ms": prover_output.get("time_prove_fs_ms", 0.0),
            "time_io_ms": prover_output.get("time_io_ms", 0.0),  # <--- PŘIDÁNO TOTO
            "proof_size_bytes": prover_output.get("proof_size_bytes", 0),
            "pure_proof_size_bytes": prover_output.get("pure_proof_size_bytes", 0)
        }

        # Return the path to the anonymous proof and the metrics
        return {
            "status": "success",
            "proof_file_path": proof_file_path,
            "scenario_msg": config["msg"],
            "pqc_details": prover_details
        }
    except Exception as e:
        return {
            "status": "error",
            "message": "Critical error in the PQC module",
            "details": str(e)
        }