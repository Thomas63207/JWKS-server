from flask import Flask, jsonify, request
import jwt
import uuid
import datetime
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# In-memory storage for keys
keys = []

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Extract the public key modulus and exponent
    public_numbers = public_key.public_numbers()
    n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
    e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip("=")
    
    return private_pem, public_pem, n, e

@app.route("/")
def home():
    return "JWKS Server is running!"

@app.route("/.well-known/jwks.json")
def jwks():
    current_time = datetime.datetime.utcnow().timestamp()
    # Filter out expired keys
    valid_keys = [key for key in keys if key["exp"] > current_time]
    
    return jsonify({"keys": valid_keys})

@app.route("/auth", methods=["POST"])
def auth():
    expired = request.args.get('expired', default='false')

    private_pem, public_pem, n, e = generate_rsa_key_pair()
    kid = str(uuid.uuid4())  # Generate a unique kid

    if expired == 'true':
        expiration = datetime.datetime.utcnow() - datetime.timedelta(seconds=10)
    else:
        expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

    payload = {'exp': expiration, 'iat': datetime.datetime.utcnow()}
    
    # Include `kid` in the JWT header
    token = jwt.encode(payload, private_pem, algorithm='RS256', headers={"kid": kid})

    # Store the public key in JWKS format with its expiration time
    keys.append({
        "kid": kid,
        "kty": "RSA",
        "use": "sig",
        "n": n,  # Base64URL encoded modulus
        "e": e,  # Base64URL encoded exponent
        "exp": expiration.timestamp()  # Store key's expiration timestamp
    })

    return jsonify({"jwt": token})

if __name__ == '__main__':
    app.run(debug=True, port=8080)
