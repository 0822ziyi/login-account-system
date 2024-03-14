import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

users_db = {}

import random


def generate_random_number():
    return random.randint(1, 1000000)

def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            bytes.fromhex(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def sign_up(username, public_key):
    if username in users_db:
        return "UsernameTaken"
    x = generate_random_number()
    encrypted_x = public_key.encrypt(
        x.to_bytes((x.bit_length() + 7) // 8,
                   padding.OAEP(
                       mgf=padding.MGF1(algorithm=hashes.SHA256()),
                       algorithm=hashes.SHA256(),
                       label=None
                   )
                   )
    challenge = encrypted_x.hex()
    return challenge

def client_response(challenge, private_key):
    encrypted_x = bytes.fromhex(challenge)
    x = private_key.decrypt(
        encrypted_x,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    x_minus_one = int.from_bytes(x, byteorder='big') - 1
    encrypted_x_minus_one = private_key.sign(
        x_minus_one.to_bytes((x_minus_one.bit_length() + 7) // 8,
                             padding.PSS(
                                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                 salt_length=padding.PSS.MAX_LENGTH
                             ),
                             hashes.SHA256()
                             )
    return encrypted_x_minus_one.hex()

def verify_and_register(username, response):
    x = generate_random_number()
    encrypted_x = x.to_bytes((x.bit_length() + 7) // 8
    expected_response = client_response(encrypted_x.hex(), users_db[username]['private_key'])
    if expected_response == response:
        users_db[username] = {'public_key': users_db[username]['public_key'], 'address': ''}
    return "Success"
    else:
    return "ChallengeIncorrect"

def login(username, address, signature):
    if username not in users_db:
        return "InvalidUsername"
    message = f"Login:{username}:{address}".encode()
    if verify_signature(message, signature, users_db[username]['public_key']):
        users_db[username]['address'] = address
        return "Success"
    else:
        return "InvalidSignature"

def find_user(username, signature):
    if username not in users_db:
        return "InvalidUsername"
    message = f"