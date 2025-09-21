from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime

# Global dictionary storing all generated keys
KEYS = {}

def generate_rsa_key_pair(key_identifier, valid_minutes=5):
    
    # Generate a new RSA key pair, store it in RSA_KEYS with an expiry timestamp.
    
    # Generate private key
    rsa_private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Extract public key
    rsa_public = rsa_private.public_key()

    # Serialize keys to PEM format
    private_pem_bytes = rsa_private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem_bytes = rsa_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Set key expiry timestamp
    key_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=valid_minutes)

    # Store in global key dictionary
    KEYS[key_identifier] = {
        'private_key': private_pem_bytes,
        'public_key': public_pem_bytes,
        'expiry': key_expiry
    }

    return private_pem_bytes, public_pem_bytes

