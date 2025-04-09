# SSH SK Attestation System

This system provides a secure way to manage SSH keys that are backed by FIDO2 security keys. It ensures that only hardware-backed and attested SSH keys can be used to access the SSH server.

## Components

1. **API Server** (`api.py`): A FastAPI application that verifies SSH key attestations and stores verified keys in a SQLite database.
2. **AuthorizedKeysCommand** (`authorized_keys_client.py`): A script that SSHD uses to check if a key is authorized.
3. **Attestation Library** (`ssh_sk_attest/`): Core library for parsing and verifying SSH key attestations.
4. **Database Models** (`models.py`): SQLite models for storing verified SSH keys.

## Setup

1. Install the package:
   ```bash
   pip install -e .
   ```

2. Start the API server:
   ```bash
   python api.py
   ```

3. Configure SSHD to use the AuthorizedKeysCommand:
   Add the following to your `/etc/ssh/sshd_config`:
   ```
   AuthorizedKeysCommand /path/to/authorized_keys_client.py %k
   AuthorizedKeysCommandUser nobody
   ```

4. Restart the SSH server:
   ```bash
   sudo systemctl restart sshd
   ```

## Usage

## Generating SSH Keys with Attestation

To generate an SSH key with attestation:

1. Generate a random challenge:
   ```bash
   openssl rand 128 > challenge.bin
   ```

2. Generate the SSH key with attestation:
   ```bash
   ssh-keygen -t ed25519-sk -f ./id -N "" -O challenge=challenge.bin -O write-attestation=attestation.bin
   ```

3. Use the generated files (`id.pub`, `attestation.bin`, `challenge.bin`) with the API to verify and store the key:

To verify and store an SSH key, send a POST request to `/key` with the following files:
- `pubkey`: The SSH public key file
- `attestation`: The attestation file
- `challenge`: The challenge file

Example using curl:
```bash
curl -X POST http://localhost:8000/key \
   -F "pubkey=@test_data/id.pub" \
   -F "attestation=@test_data/attestation.bin" \
   -F "challenge=@test_data/challenge.bin"
```

### Checking a Key

To check if a specific key is authorized, send a GET request to `/key` with the public key as a query parameter:
```bash
curl "http://localhost:8000/key?pubkey=AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIGmno0S21EOoxKXQX7HMFiPsdhaBR/ENuFf7q4AP9CPbAAAABHNzaDo="
```

### Listing Authorized Keys

To list all authorized keys, send a GET request to `/keys`:
```bash
curl "http://localhost:8000/keys"
```

## Development

The project is organized as a Python package with the following structure:
- `ssh_sk_attest/`: Core library package
  - `attestation.py`: Attestation parsing and verification
- `api.py`: FastAPI server implementation
- `models.py`: Database models
- `authorized_keys_client.py`: SSHD integration script
- `setup.py`: Package configuration
