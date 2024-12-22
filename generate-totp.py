import pyotp

totp_secret = "FDRAWPC5UIMNDS3XOUMQLIO734MQS5GH"  # Replace with the admin's TOTP secret
totp = pyotp.TOTP(totp_secret)
print(totp.now())
