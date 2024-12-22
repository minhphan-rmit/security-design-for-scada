import pyotp
import time

# Shared secret (Base32 encoded)
shared_secret = "JBSWY3DPEHPK3PXP"

# Create a TOTP object
totp = pyotp.TOTP(shared_secret)

# Generate an OTP for the current time
current_otp = totp.now()
print(f"Generated OTP: {current_otp}")

# Verify the OTP with no valid window (default)
print("Verify exact OTP:", totp.verify(current_otp))

# Simulate clock drift: Verify OTP with a ±30s window
time.sleep(31)  # Wait for 31 seconds to enter the next time step
print("Verify with drift:", totp.verify(current_otp, valid_window=1))
