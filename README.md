
# CCF Blockchain Network

The CCF (Confidential Consortium Framework) Blockchain Network is a framework designed to provide a highly secure, performant, and confidential blockchain solution. It's particularly well-suited for consortiums that require a high degree of privacy and transaction integrity. Here are some key features of the CCF Blockchain Network:

## Key Features

- **Confidential Transactions**: CCF supports transactions that remain confidential among involved parties, ensuring privacy and security.

- **High Throughput and Low Latency**: It is optimized for high transaction throughput and low latency, making it ideal for enterprise-grade applications.

- **Governance Model**: CCF provides a flexible governance model, allowing consortiums to manage the network effectively.

- **Compatibility with Popular Programming Languages**: It supports smart contracts written in popular programming languages, enhancing its accessibility and usability.

## Usage in Our Project

In our project, `ccf_utilities`, we leverage the CCF Blockchain Network to provide secure and confidential transaction processing. The utilities we've developed aid in managing user identities, proposals, and ballots, ensuring seamless integration with the CCF ecosystem.

The `ccf_utilities` package encapsulates these functionalities, simplifying the process of integrating with the CCF Blockchain Network.




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




