# jwks_server.py
"""
JWKS Server
"""

from flask import Flask, jsonify, request, make_response
import uuid
from key_generation import generate_rsa_key_pair, KEYS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import datetime
import jwt

# Server Initialization
app = Flask(__name__)
SERVER_PORT = 8080

# Helper Function
def int_to_base64url(value: int) -> str:
    #Encode an integer as Base64 URL without padding (used in JWKS).
    byte_data = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(byte_data).rstrip(b'=').decode('ascii')


# Generate initial key
initial_key_id = str(uuid.uuid4())
initial_private, initial_public = generate_rsa_key_pair(initial_key_id)


# JWKS Endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    
    #Returns all active public keys in JWKS format.
    #Only keys that haven't expired are included.
    
    jwks_keys = []

    current_time = datetime.datetime.utcnow()
    for key_id, key_info in KEYS.items():
        if key_info['expiry'] > current_time:
            pubkey_obj = serialization.load_pem_public_key(
                key_info['public_key'], backend=default_backend()
            )
            numbers = pubkey_obj.public_numbers()
            jwks_keys.append({
                'kid': key_id,
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': int_to_base64url(numbers.n),
                'e': int_to_base64url(numbers.e),
            })

    return jsonify({'keys': jwks_keys})


# Auth Endpoint
@app.route('/auth', methods=['POST'])
def issue_jwt():
    
    #Issues a JWT for a fake user.
    #Add ?expired=true to get a token with an expiration in the past.
    
    body = request.json
    if not body or 'username' not in body or 'password' not in body:
        return make_response(jsonify({'message': 'Invalid request'}), 400)

    request_expired = request.args.get('expired', 'false').lower() == 'true'
    current_time = datetime.datetime.utcnow()

    # Select key for signing
    if request_expired:
        # Try to find an expired key
        expired_key_ids = [k for k, v in KEYS.items() if v['expiry'] < current_time]
        if expired_key_ids:
            selected_kid = expired_key_ids[0]
        else:
            # Create a key that's already expired
            selected_kid = str(uuid.uuid4())
            priv, pub = generate_rsa_key_pair(selected_kid)
            KEYS[selected_kid]['expiry'] = current_time - datetime.timedelta(minutes=1)

        iat_timestamp = int(current_time.timestamp())
        exp_timestamp = int((current_time - datetime.timedelta(minutes=1)).timestamp())

    else:
        # Use an active key or create a new one
        active_key_ids = [k for k, v in KEYS.items() if v['expiry'] > current_time]
        if active_key_ids:
            selected_kid = active_key_ids[0]
        else:
            selected_kid = str(uuid.uuid4())
            priv, pub = generate_rsa_key_pair(selected_kid)

        iat_timestamp = int(current_time.timestamp())
        exp_timestamp = int(KEYS[selected_kid]['expiry'].timestamp())

    signing_key = KEYS[selected_kid]['private_key']

    # Create JWT payload
    jwt_payload = {
        'sub': body['username'],
        'iat': iat_timestamp,
        'exp': exp_timestamp
    }

    token = jwt.encode(
        jwt_payload,
        signing_key,
        algorithm='RS256',
        headers={'kid': selected_kid}
    )

    return jsonify({'token': token})


# Main
if __name__ == '__main__':
    app.run(port=SERVER_PORT)
