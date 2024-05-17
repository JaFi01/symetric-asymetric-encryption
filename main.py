from fastapi import FastAPI, HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json

app = FastAPI()

symmetric_key = None
asymmetric_private_key = None
asymmetric_public_key = None


@app.get("/symmetric/key")
def get_symmetric_key():
    global symmetric_key
    symmetric_key = Fernet.generate_key()
    return {"key": symmetric_key.hex()}


@app.post("/symmetric/key")
def set_symmetric_key(key: str):
    global symmetric_key
    try:
        symmetric_key = bytes.fromhex(key)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key format, please provide a valid HEX key.")
    return {"message": "Symmetric key set successfully."}


@app.post("/symmetric/encode")
def symmetric_encode(message: str):
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set.")
    fernet = Fernet(symmetric_key)
    encrypted_message = fernet.encrypt(message.encode())
    return {"encrypted_message": encrypted_message.hex()}


@app.post("/symmetric/decode")
def symmetric_decode(encrypted_message: str):
    if symmetric_key is None:
        raise HTTPException(status_code=400, detail="Symmetric key not set.")
    fernet = Fernet(symmetric_key)
    decrypted_message = fernet.decrypt(bytes.fromhex(encrypted_message))
    return {"decrypted_message": decrypted_message.decode()}


@app.get("/asymmetric/key")
def get_asymmetric_key():
    global asymmetric_private_key, asymmetric_public_key
    asymmetric_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    asymmetric_public_key = asymmetric_private_key.public_key()
    return {"private_key": asymmetric_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()).decode(),
        "public_key": asymmetric_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}


@app.get("/asymmetric/key/ssh")
def get_asymmetric_key_ssh():
    global asymmetric_private_key, asymmetric_public_key
    if asymmetric_private_key is None or asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric keys not generated.")
    ssh_public_key = asymmetric_public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode()
    return {"private_key": asymmetric_private_key.private_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()).decode(),
        "public_key": ssh_public_key}


@app.post("/asymmetric/key")
def set_asymmetric_key(keys: dict):
    global asymmetric_private_key, asymmetric_public_key
    private_key_bytes = keys.get("private_key")
    public_key_bytes = keys.get("public_key")
    if private_key_bytes is None or public_key_bytes is None:
        raise HTTPException(status_code=400, detail="Both private and public keys are required.")
    try:
        asymmetric_private_key = serialization.load_pem_private_key(
            private_key_bytes.encode(),
            password=None,
            backend=default_backend()
        )
        asymmetric_public_key = serialization.load_pem_public_key(
            public_key_bytes.encode(),
            backend=default_backend()
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid key format.")
    return {"message": "Asymmetric keys set successfully."}


@app.post("/asymmetric/verify")
def asymmetric_verify(message: str):
    global asymmetric_private_key
    if asymmetric_private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric private key not set.")
    signature = asymmetric_private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {"signature": signature.hex()}


@app.post("/asymmetric/sign")
def asymmetric_sign(message: str, signature: str):
    global asymmetric_public_key
    if asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric public key not set.")
    try:
        asymmetric_public_key.verify(
            bytes.fromhex(signature),
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception:
        return {"verified": False}
    return {"verified": True}


@app.post("/asymmetric/encode")
def asymmetric_encode(message: str):
    global asymmetric_public_key
    if asymmetric_public_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric public key not set.")
    encrypted_message = asymmetric_public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"encrypted_message": encrypted_message.hex()}


@app.post("/asymmetric/decode")
def asymmetric_decode(encrypted_message: str):
    global asymmetric_private_key
    if asymmetric_private_key is None:
        raise HTTPException(status_code=400, detail="Asymmetric private key not set.")
    decrypted_message = asymmetric_private_key.decrypt(
        bytes.fromhex(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {"decrypted_message": decrypted_message.decode()}
