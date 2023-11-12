# ccf_utilities

`ccf_utilities` is a Python package designed to simplify and automate various tasks when working with a Confidential Consortium Framework (CCF) network. It includes functions for user management, secure request handling, voting, and retrieving network metrics.

## Features

- User certificate creation and management
- Secure submission of proposals and ballots
- Checking network metrics and status

## Installation

To install `ccf_utilities`, simply run the following command:

```bash
pip install ccf_utilities
```
## Usage
Below are some examples of how to use `ccf_utilities`:
## Create Users
Generate certificates for users:
```python
ccf_utilities.create_users(num_users=5)
```

## Send Secure Requests
Submit proposals securely:
```python
response_code, response_content = ccf_utilities.send_secure_request(
    url="https://127.0.0.1:8000/gov/proposals",
    request_data_path="@proposal_data.json",
    signing_privk="member0_privk.pem",
    signing_cert="member0_cert.pem"
)
```

## Vote on Proposals
Send votes for proposals:

```python
response_code, response_content = ccf_utilities.send_ballot_request(
    server_url="https://127.0.0.1:8000",
    proposal_id="proposal_id_here",
    data_file_path="vote_accept.json",
    signing_privk_path="member1_privk.pem",
    signing_cert_path="member1_cert.pem"
)
```

## Delete User Files
Remove files associated with users:

```python
ccf_utilities.delete_user_files(num_users=5)
```




