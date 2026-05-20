import requests
import time

# ********************************Basic Information****************************************
# This module acts as an Automated Testing Utility
# It automatically generates 5 users with different combinations of credentials
# It simulates the complete credential lifecycle: requesting issuance from the Authority and securely pushing the resulting data to the local Wallet.
# *****************************************************************************************

# Network configuration for the FastAPI backend
BASE_URL = "http://localhost:8000"
# Global testing password for the encrypted database (User master password for enter to the wallet)
PASSWORD = "test"

# List of 5 different users for test scenarios
test_users = [
    {
        "first_name": "Jan", "last_name": "Novak", "date_of_birth": "1990-01-01",
        "id_card_number": "111111", "email": "jan@test.cz", "birth_place": "Prague",
        "street": "Dlouha 1", "zip_code": "11000", "city": "Prague",
        "is_adult": 1, "has_license": 1, "clean_record": 1 # All valid (Ideal citizen)
    },
    {
        "first_name": "Petr", "last_name": "Dvorak", "date_of_birth": "2010-05-05",
        "id_card_number": "222222", "email": "petr@test.cz", "birth_place": "Brno",
        "street": "Kratka 2", "zip_code": "60200", "city": "Brno",
        "is_adult": 0, "has_license": 0, "clean_record": 1 # Underage, no license
    },
    {
        "first_name": "Karel", "last_name": "Zly", "date_of_birth": "1985-03-03",
        "id_card_number": "333333", "email": "karel@test.cz", "birth_place": "Ostrava",
        "street": "Temna 3", "zip_code": "70200", "city": "Ostrava",
        "is_adult": 1, "has_license": 1, "clean_record": 0 # Criminal record (Fails HR check)
    },
    {
        "first_name": "Eva", "last_name": "Mlada", "date_of_birth": "2007-08-08",
        "id_card_number": "444444", "email": "eva@test.cz", "birth_place": "Plzen",
        "street": "Nova 4", "zip_code": "30100", "city": "Plzen",
        "is_adult": 0, "has_license": 1, "clean_record": 1 # Underage, but has A1 license
    },
    {
        "first_name": "Marie", "last_name": "Slusna", "date_of_birth": "1970-12-12",
        "id_card_number": "555555", "email": "marie@test.cz", "birth_place": "Liberec",
        "street": "Stara 5", "zip_code": "46001", "city": "Liberec",
        "is_adult": 1, "has_license": 0, "clean_record": 1 # Adult, but no license
    }
]

print("Starting automatic generation of 5 test users...")

start_total_time = time.time()

#Simulates the HTTP interactions between the User, the Issuer, and the Wallet.
for user in test_users:
    print(f"Issuing credentials for: {user['first_name']} {user['last_name']}...")


    try:
        #Simulate the user submitting their data to the Trusted Authority
        issue_response = requests.post(f"{BASE_URL}/authority/issue", json=user)

        if issue_response.status_code == 200:
            issue_data = issue_response.json()
            user_id = issue_data["user_id"]

            # The Authority responds with the generated .bin credential paths.
            # The client-side logic now forwards this data to the local Wallet for AES-GCM encryption.
            wallet_payload = {
                "user_id": user_id,
                "personal_data": issue_data["personal_data"],
                "wallet_files": issue_data["wallet_files"],
                "wallet_password": PASSWORD
            }

            wallet_response = requests.post(f"{BASE_URL}/wallet/receive", json=wallet_payload)

            if wallet_response.status_code == 200:
                print(f"  Success: Added to wallet (ID: {user_id})")
            else:
                print(f"  Error saving to wallet: {wallet_response.text}")
        else:
            print(f"  Error during issuance at Authority: {issue_response.text}")

    except requests.exceptions.ConnectionError:
        print("Error: Cannot connect to the server. Is FastAPI running on localhost:8000?")
        break

    # Short pause to ensure C code and disk writes complete safely
    ## Safety buffer: Prevents overwhelming the filesystem during rapid sequential C-kernel executions
    time.sleep(1.5)

    end_total_time = time.time()
    total_duration = end_total_time - start_total_time

print(f"\nDONE! Generated 5 users in {total_duration:.2f} seconds.")
print("You can now open the wallet in the web application using the password 'test'.")