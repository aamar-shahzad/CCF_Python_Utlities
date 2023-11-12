# user_management.py
import json
import requests
import subprocess
import time
import os
import glob
from urllib.parse import urlparse
import hashlib
import base64

from ccf_utilities.key_generator import create_certificate
from ccf_utilities.voting import get_certificate_fingerprint, send_ballot_request
from .config import SERVER_URL, NUM_USERS

def delete_user_files(num_users=NUM_USERS):
     for i in range(num_users):
            # File names based on user index
        cert_file = f"user{i}_cert.pem"
        priv_key_file = f"user{i}_privk.pem"
        enc_priv_file = f"user{i}_enc_privk.pem"
        enc_pub_file = f"user{i}_enc_pubk.pem"

        # Delete the files if they exist
        for file in [cert_file, priv_key_file, enc_priv_file, enc_pub_file]:
            if os.path.exists(file):
                os.remove(file)
                print(f"Deleted {file}")
            else:
                print(f"{file} does not exist")

        # Delete all JSON files related to the user
        for json_file in glob.glob(f"set_user{i}*.json"):
            os.remove(json_file)
            print(f"Deleted {json_file}")
            
            

def send_secure_request(url, request_data_path, signing_privk, signing_cert, command="post"):
    def read_request_data(request_path):
        if request_path.startswith('@'):
            with open(request_path[1:], 'r') as file:
                return file.read()
        else:
            return request_path

    def calculate_digest(data):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data.encode('utf-8'))
        return base64.b64encode(sha256_hash.digest()).decode()

    def create_signature(string_to_sign, priv_key_path):
        process = subprocess.Popen(
            ['openssl', 'dgst', '-sha384', '-sign', priv_key_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        signature, _ = process.communicate(string_to_sign.encode())
        return base64.b64encode(signature).decode().replace('\n', '')

    def prepare_string_to_sign(method, url, digest, data_length):
        parsed_url = urlparse(url)
        path = parsed_url.path
        return f"(request-target): {method.lower()} {path}\ndigest: SHA-256={digest}\ncontent-length: {data_length}"

    def get_cert_key_id(cert_path):
        proc = subprocess.Popen(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output, _ = proc.communicate()
        fingerprint = output.decode().split('=')[1].replace(':', '').lower().replace('\n', '')
        return fingerprint

    request_data = read_request_data(request_data_path)
    request_digest = calculate_digest(request_data)
    string_to_sign = prepare_string_to_sign(command, url, request_digest, str(len(request_data)))
    signature = create_signature(string_to_sign, signing_privk)
    key_id = get_cert_key_id(signing_cert)

    headers = {
        "Digest": f"SHA-256={request_digest}",
        "Authorization": f'Signature keyId="{key_id}",algorithm="hs2019",headers="(request-target) digest content-length",signature="{signature}"'
    }

    response = requests.post(url, data=request_data, headers=headers, verify='service_cert.pem')
    return response.status_code, response.text




def main_process(num_initial_users=NUM_USERS):
    # Generate keys and certificates for all users
    for i in range(num_initial_users):
        create_certificate(f"user{i}")

    # Submit proposal and voting for each user
    for i in range(num_initial_users):
        user_name = f"user{i}"
        user_cert_path = f"{user_name}_cert.pem"
        user_key_path = f"{user_name}_privk.pem"

        # Member0 submits the proposal
        status_code, response_json = send_secure_request(SERVER_URL + "/gov/proposals", f"@set_{user_name}.json", "member0_privk.pem", "member0_cert.pem", "post")
        print("proposal_id",json.loads(response_json)['proposal_id'])
        proposal_id=json.loads(response_json)['proposal_id']

        # Other members vote
        for j in range(1, 3):  # Assuming 2 other members (member1 and member2)
            vote_status, response_json = send_ballot_request(SERVER_URL, proposal_id, "vote_accept.json", f"member{j}_privk.pem", f"member{j}_cert.pem")
            # print("vote_status",vote_status,"response_json",response_json)
            if vote_status != 200:
                print(f"Voting failed for {user_name} by member{j}")
                continue
            time.sleep(1)  # Delay for processing

        # Create account for the user
        user_id=get_certificate_fingerprint(user_cert_path)
        print("Actual id",user_id) 
   