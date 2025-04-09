#!/usr/bin/env python3

import sys
import requests
import logging
from typing import Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API configuration
API_BASE_URL = "http://localhost:8000"  # Change this to your API server URL

def get_key(pubkey: str) -> Optional[str]:
    """Get a public key from the database.
    
    Args:
        pubkey: Base64-encoded public key
        
    Returns:
        The public key if it exists, None otherwise
    """
    try:
        response = requests.get(
            f"{API_BASE_URL}/key",
            params={"pubkey": pubkey}
        )
        
        if response.status_code == 404:
            return None
            
        response.raise_for_status()
        data = response.json()
        return data["key_type"] + " " + data["public_key"] + " " + data["comment"]
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting key: {str(e)}")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: authorized_keys_client.py <pubkey>", file=sys.stderr)
        sys.exit(1)

    pubkey = sys.argv[1]
    
    if not pubkey:
        logger.error("No public key provided")
        sys.exit(1)
    
    # Get the key from the API
    stored_key = get_key(pubkey)
    if stored_key:
        print(stored_key)
        sys.exit(0)
    else:
        logger.info(f"Key not found.")
        sys.exit(1)

if __name__ == "__main__":
    main() 