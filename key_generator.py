# key_generator.py
import subprocess
import sys
import json

DEFAULT_CURVE = "secp384r1"
DIGEST_SHA384 = "sha384"


RSA_SIZE = 2048


DEFAULT_CURVE = "secp384r1"
FAST_CURVE = "secp256r1"
SUPPORTED_CURVES = [DEFAULT_CURVE, FAST_CURVE]

DIGEST_SHA384 = "sha384"
DIGEST_SHA256 = "sha256"



def generate_keys(name, curve=DEFAULT_CURVE, generate_encryption_key=False):
    if not name:
        print("Error: The name of the participant should be specified (e.g. member0 or user1)")
        sys.exit(1)

    if curve not in SUPPORTED_CURVES:
        print(f"{curve} curve is not in {SUPPORTED_CURVES}")
        sys.exit(1)

    digest = DIGEST_SHA384 if curve == DEFAULT_CURVE else DIGEST_SHA256

    cert = f"{name}_cert.pem"
    privk = f"{name}_privk.pem"

    print(f"-- Generating identity private key and certificate for participant \"{name}\"...")
    print(f"Identity curve: {curve}")

    subprocess.run(["openssl", "ecparam", "-out", privk, "-name", curve, "-genkey"], check=True)
    subprocess.run(["openssl", "req", "-new", "-key", privk, "-x509", "-nodes", "-days", "365", "-out", cert, f"-{digest}", "-subj", f"/CN={name}"], check=True)

    print(f"Identity private key generated at: {privk}")
    print(f"Identity certificate generated at: {cert} (to be registered in CCF)")

    if generate_encryption_key:
        print(f"-- Generating RSA encryption key pair for participant \"{name}\"...")

        enc_priv = f"{name}_enc_privk.pem"
        enc_pub = f"{name}_enc_pubk.pem"

        subprocess.run(["openssl", "genrsa", "-out", enc_priv, str(RSA_SIZE)], check=True)
        subprocess.run(["openssl", "rsa", "-in", enc_priv, "-pubout", "-out", enc_pub], check=True)

        print(f"Encryption private key generated at: {enc_priv}")
        print(f"Encryption public key generated at: {enc_pub} (to be registered in CCF)")



# CA certificate creator function
def create_certificate(cert_name):
    cert_file = f"{cert_name}_cert.pem"
    set_user_file = f"set_{cert_name}.json"
    
    # Call the generate_keys function (make sure to include it in your script)
    generate_keys(cert_name)

    # Read the certificate file and format it
    with open(cert_file, 'r') as file:
        cert_content = file.read().replace('\n', '\n')

    # Create the JSON content
    user_json = {
        "actions": [
            {
                "name": "set_user",
                "args": {
                    "cert": cert_content
                }
            }
        ]
    }

    # Write the JSON to a file
    with open(set_user_file, 'w') as file:
        json.dump(user_json, file, indent=2)
    print(f"JSON file created at: {set_user_file}")
  