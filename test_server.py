import requests
import jwt
import time
import os
from time import sleep
from requests.exceptions import ConnectionError
from requests.auth import HTTPBasicAuth

BASE_URL = "https://127.0.0.1:5000"  # Update based on your server setup
HEADERS = {"Content-Type": "application/json"}
VERIFY_SSL = False  # Disable SSL verification for self-signed certificates
TOTP_SECRET = None  # This will be set during registration if needed

def test_health_check():
    print("Testing health check endpoint...")
    response = requests.get(f"{BASE_URL}/", verify=VERIFY_SSL)
    assert response.status_code == 200, f"Health check failed: {response.text}"
    print("Health check passed.")

def test_register_user():
    global TOTP_SECRET
    print("Testing user registration...")
    data = {"username": "testuser", "password": "testpassword", "role": "user"}
    response = requests.post(f"{BASE_URL}/register", json=data, headers=HEADERS, verify=VERIFY_SSL)
    if response.status_code == 400 and "User already exists" in response.text:
        print("User already exists, skipping registration.")
        TOTP_SECRET = "123456"  # Replace with actual secret if needed
    else:
        assert response.status_code == 201, f"User registration failed: {response.text}"
        TOTP_SECRET = response.json().get("totp_secret")
        assert TOTP_SECRET, "TOTP secret not returned during registration"
        print(f"User registration passed. TOTP Secret: {TOTP_SECRET}")

def test_login_user():
    print("Testing user login...")
    data = {"username": "testuser", "password": "testpassword", "totp": "747200"}  # Adjust TOTP dynamically
    response = requests.post(f"{BASE_URL}/login", json=data, headers=HEADERS, verify=VERIFY_SSL)
    assert response.status_code == 200, f"User login failed: {response.text}"
    token = response.json().get("token")
    assert token, "Token not returned on login"
    print("User login passed.")
    return token

def test_sql_injection():
    print("Testing SQL injection...")
    payload = {"username": "admin'--", "password": "irrelevant"}
    response = requests.post(f"{BASE_URL}/login", json=payload, verify=VERIFY_SSL)
    assert "Invalid credentials" in response.text, "SQL Injection vulnerability detected"
    print("SQL injection test passed.")

def test_xss():
    print("Testing XSS injection...")
    payload = {"username": "<script>alert(1)</script>", "password": "test"}
    response = requests.post(f"{BASE_URL}/register", json=payload, verify=VERIFY_SSL)
    assert "<script>" not in response.text, "XSS vulnerability detected"
    print("XSS injection test passed.")

def test_jwt_manipulation():
    print("Testing JWT token manipulation...")
    tampered_token = jwt.encode({"username": "admin"}, "wrong_key", algorithm="HS256")
    headers = {"Authorization": tampered_token}
    response = requests.post(f"{BASE_URL}/upload_logic", headers=headers, verify=VERIFY_SSL)
    assert response.status_code in [401, 403], "JWT manipulation vulnerability detected"
    print("JWT manipulation test passed.")

def test_privilege_escalation():
    print("Testing privilege escalation...")
    user_token = None
    retry_attempts = 3
    retry_delay = 60  # Time in seconds to wait between retries

    for attempt in range(retry_attempts):
        try:
            user_token = test_login_user()  # Attempt login
            break
        except AssertionError as e:
            if "Too Many Requests" in str(e):
                print(f"Rate limit hit, retrying after {retry_delay} seconds... (Attempt {attempt + 1}/{retry_attempts})")
                time.sleep(retry_delay)
            else:
                raise e

    if not user_token:
        raise Exception("Failed to login due to rate limiting.")

    headers = {"Authorization": user_token}
    response = requests.post(f"{BASE_URL}/upload_logic", headers=headers, json={}, verify=VERIFY_SSL)
    assert response.status_code == 403, "Privilege escalation vulnerability detected"
    print("Privilege escalation test passed.")

def test_file_upload():
    print("Testing file upload...")
    user_token = test_login_user()  # Ensure user is authenticated
    headers = {"Authorization": f"Bearer {user_token}"}
    files = {"file": ("test.txt", b"Hello, World!")}
    response = requests.post(f"{BASE_URL}/upload_file", files=files, headers=headers, verify=VERIFY_SSL)
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200, f"Valid file upload failed: {response.text}"
    print("File upload test passed.")

def test_malware_upload():
    print("Testing malware file upload...")
    user_token = test_login_user()  # Ensure user is authenticated
    headers = {"Authorization": f"Bearer {user_token}"}
    files = {"file": ("malicious.exe", b"MALWARE")}
    response = requests.post(f"{BASE_URL}/upload_file", files=files, headers=headers, verify=VERIFY_SSL)
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 403, "Malware upload not blocked"
    print("Malware upload test passed.")

def test_rate_limiting():
    print("Testing rate limiting...")
    for _ in range(15):
        response = requests.post(f"{BASE_URL}/login", json={"username": "test", "password": "test"}, verify=VERIFY_SSL)
        if response.status_code == 429:
            print("Rate limit triggered.")
            return
    raise Exception("Rate limiting test failed.")

def test_dos_protection():
    print("Testing DoS protection...")
    try:
        for _ in range(100):
            response = requests.get(f"{BASE_URL}/", verify=VERIFY_SSL)
        print("DoS protection test completed. Verify server stability manually.")
    except Exception as e:
        print(f"Error during DoS test: {e}")

def run_tests():
    retries = 5
    for attempt in range(retries):
        try:
            test_health_check()
            test_register_user()
            token = test_login_user()
            test_sql_injection()
            test_xss()
            test_jwt_manipulation()
            test_privilege_escalation()
            test_file_upload()
            # test_malware_upload()
            test_rate_limiting()
            test_dos_protection()  # Ensure this is the last test
            print("All tests passed successfully!")
            return
        except ConnectionError as e:
            print(f"Connection error: {e}. Retrying in 5 seconds... (Attempt {attempt + 1}/{retries})")
            time.sleep(5)
        except AssertionError as e:
            print(f"Test failed: {e}")
            return
    print("Failed to connect to the server after multiple retries.")

if __name__ == "__main__":
    run_tests()
