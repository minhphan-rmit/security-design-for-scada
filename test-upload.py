import requests
import os

# Constants
BASE_URL = "http://127.0.0.1:5000"  # Replace with your server's URL
LOGIN_ENDPOINT = "/login"
UPLOAD_ENDPOINT = "/upload_file"

# Helper function to login and get JWT token
def get_jwt_token(username, password, totp):
    login_data = {
        "username": username,
        "password": password,
        "totp": totp
    }
    response = requests.post(BASE_URL + LOGIN_ENDPOINT, json=login_data)
    if response.status_code == 200:
        return response.json().get("token")
    else:
        print("Login failed:", response.status_code, response.json())
        return None

# Helper function to upload a file
def upload_file(file_path, jwt_token):
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        headers = {
            'Authorization': f'Bearer {jwt_token}'  # Include the token for authentication
        }
        response = requests.post(BASE_URL + UPLOAD_ENDPOINT, files=files, headers=headers)
    return response

def main():
    # Login credentials
    username = "user"  # Replace with your username
    password = "userpassword"  # Replace with your password
    totp = "747200"  # Replace with a valid TOTP code

    # Get JWT token
    jwt_token = get_jwt_token(username, password, totp)
    if not jwt_token:
        print("Failed to retrieve JWT token.")
        return

    # Create test files
    valid_file_path = "test_valid.txt"
    invalid_file_path = "test_invalid.exe"

    try:
        # Create a valid file
        with open(valid_file_path, "w") as f:
            f.write("This is a valid file for testing.")

        # Create an invalid file
        with open(invalid_file_path, "w") as f:
            f.write("This is an invalid file for testing.")

        # Upload valid file
        print("Testing valid file upload...")
        valid_response = upload_file(valid_file_path, jwt_token)
        print("Valid File Response:", valid_response.status_code, valid_response.json())

        # Upload invalid file
        print("Testing invalid file upload...")
        invalid_response = upload_file(invalid_file_path, jwt_token)
        print("Invalid File Response:", invalid_response.status_code, invalid_response.json())

    finally:
        # Clean up test files
        if os.path.exists(valid_file_path):
            os.remove(valid_file_path)
        if os.path.exists(invalid_file_path):
            os.remove(invalid_file_path)

if __name__ == "__main__":
    main()
