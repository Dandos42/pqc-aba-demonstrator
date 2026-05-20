from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import subprocess
import json
import os

# ********************************Basic info****************************************
# This module simulates the Verifier (e.g., e-shop, HR department, or police check)
# It orchestrates the mathematical validation of the ZKP
# it processes an anonymous binary proof
# without ever accessing the Holder's wallet, password, PII (data minimalization)
# **********************************************************************************

router = APIRouter()

# Setup working directories for Docker integration
BASE_DIR = "/home/lac/_build"
VERIFIER_EXE = os.path.join(BASE_DIR, "verify_proof")

#Data model for the verification request.
# it contains NO personal data—only an anonymous session ID, the verification context, and the path to the ephemeral ZKP binary
class PureVerifyRequest(BaseModel):
    user_id: str
    scenario_msg: str
    proof_file_path: str

#Invokes the isolated C-kernel to mathematically verify the ZKP matrix
@router.post("/verify")
async def verify_credential(request: PureVerifyRequest):
    # Check if the proof file exists on the disk
    if not os.path.exists(request.proof_file_path):
        raise HTTPException(status_code=404, detail="The proof file was not found.")

    # Copy the environment variables from the operating system
    env_vars = os.environ.copy()
    env_vars["ASAN_OPTIONS"] = "detect_leaks=0"  # Disable memory error detection notifications.

    try:
        # VERIFIER - Checks the generated matrix
        #Execute the compiled C-kernel to verify the public statement against the blinded proof
        verifier_result = subprocess.run(
            [VERIFIER_EXE, request.proof_file_path],
            capture_output=True, text=True, check=True, env=env_vars
        )

        ## Parse the validation result and hardware benchmarks
        verifier_output = json.loads(verifier_result.stdout.strip())

        # Extract performance metrics for the frontend benchmark grid
        verifier_details = {
            "is_valid": verifier_output.get("is_valid", False),
            "message": verifier_output.get("message", ""),
            "time_verify_total_ms": verifier_output.get("time_verify_total_ms", 0.0),
            "time_ram_ms": verifier_output.get("time_ram_ms", 0.0),  # <--- PŘIDÁNO TOTO
            "time_recon_ms": verifier_output.get("time_recon_ms", 0.0),
            "time_verify_math_ms": verifier_output.get("time_verify_math_ms", 0.0),
            "pk_size_bytes": verifier_output.get("pk_size_bytes", 0),  # <--- PŘIDÁNO TOTO
            "peak_ram_kb": verifier_output.get("peak_ram_kb", 0)  # <--- PŘIDÁNO TOTO
        }

        # Receiving the results
        # Return the cryptographic decision (Access Granted/Denied) and metrics
        return {
            "status": "success",
            "scenario": request.scenario_msg,
            "user_id": request.user_id,  # Only the anonymous identifier
            "access_granted": verifier_details["is_valid"],
            "pqc_details": verifier_details
        }

    # Error Handling
    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "access_granted": False,
            "message": "Critical error in the PQC verification module.",
            "details": e.stderr.strip() if e.stderr else "Unknown error"
        }
    except json.JSONDecodeError:
        return {
            "status": "error",
            "access_granted": False,
            "message": "The C program did not return valid JSON."
        }
    finally:
        # Clearing the cache and deleting ZKP files
        # Securely delete the ZKP binary from the disk after verification.
        if os.path.exists(request.proof_file_path):
            os.remove(request.proof_file_path)