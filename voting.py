import requests
import json
from urllib.parse import urlparse
import subprocess
import hashlib
import base64





# sending voting to add  the user based on proposal id 

def send_ballot_request(server_url, proposal_id, data_file_path, signing_privk_path, signing_cert_path):
    def read_request_data(file_path):
        with open(file_path, 'r') as file:
            return file.read()

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

    def prepare_string_to_sign(url, digest, data_length):
        parsed_url = urlparse(url)
        path = parsed_url.path
        return f"(request-target): post {path}\ndigest: SHA-256={digest}\ncontent-length: {data_length}"

    def get_cert_key_id(cert_path):
        proc = subprocess.Popen(
            ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output, _ = proc.communicate()
        fingerprint = output.decode().split('=')[1].replace(':', '').lower().replace('\n', '')
        return fingerprint

    url = f"{server_url}/gov/proposals/{proposal_id}/ballots"
    request_data = read_request_data(data_file_path)
    request_digest = calculate_digest(request_data)
    string_to_sign = prepare_string_to_sign(url, request_digest, str(len(request_data)))
    signature = create_signature(string_to_sign, signing_privk_path)
    key_id = get_cert_key_id(signing_cert_path)

    headers = {
        "Digest": f"SHA-256={request_digest}",
        "Authorization": f'Signature keyId="{key_id}",algorithm="hs2019",headers="(request-target) digest content-length",signature="{signature}"',
        "Content-Type": "application/json"
    }

    response = requests.post(url, data=request_data, headers=headers, verify='service_cert.pem')
    return response.status_code, response.json()






# creation of user id based on certifacte 
def get_certificate_fingerprint(cert_path):
    process = subprocess.Popen(
        ['openssl', 'x509', '-in', cert_path, '-noout', '-fingerprint', '-sha256'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    output, _ = process.communicate()
    fingerprint = output.decode().split('=')[1].replace(':', '').lower().strip()
    return fingerprint