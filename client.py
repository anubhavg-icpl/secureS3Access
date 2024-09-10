import requests
import base64
import os
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from requests.exceptions import RequestException

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
API_URL = 'https://your-api-gateway-url/your-stage'
PUBLIC_KEY_PATH = 'path/to/public_key.pem'

def load_public_key():
    try:
        with open(PUBLIC_KEY_PATH, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key
    except Exception as e:
        logger.error(f"Failed to load public key: {str(e)}")
        raise

def verify_signature(public_key, signature, challenge):
    try:
        public_key.verify(
            signature,
            challenge.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        logger.warning("Signature verification failed")
        return False
    except Exception as e:
        logger.error(f"Error during signature verification: {str(e)}")
        raise

def get_file_from_s3(file_key):
    public_key = load_public_key()
    challenge = base64.b64encode(os.urandom(32)).decode()

    try:
        response = requests.post(API_URL, json={
            'file_key': file_key,
            'challenge': challenge
        }, timeout=10)
        response.raise_for_status()
    except RequestException as e:
        logger.error(f"Failed to send request: {str(e)}")
        return None

    try:
        data = response.json()
        download_url = data['download_url']
        signature = base64.b64decode(data['signature'])
    except (KeyError, ValueError) as e:
        logger.error(f"Invalid response format: {str(e)}")
        return None

    if verify_signature(public_key, signature, challenge):
        logger.info(f"Signature verified. Download URL: {download_url}")
        return download_url
    else:
        logger.warning("Signature verification failed. The server may be compromised.")
        return None

def download_file(url, local_path):
    try:
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(local_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        logger.info(f"File downloaded successfully to {local_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to download file: {str(e)}")
        return False

if __name__ == "__main__":
    file_key = 'example.txt'
    download_url = get_file_from_s3(file_key)
    if download_url:
        download_file(download_url, 'downloaded_file.txt')
