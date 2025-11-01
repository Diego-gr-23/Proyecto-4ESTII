# crypto_core.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import base64, json, os
from crypto_nodes import KeyPair, MessageNode, SignatureNode


# Hash FNV-1a

class FNV1aHash:
    @staticmethod
    def compute(data: bytes) -> str:
        FNV_offset = 0xcbf29ce484222325
        FNV_prime = 0x100000001b3
        h = FNV_offset
        for b in data:
            h ^= b
            h = (h * FNV_prime) & 0xFFFFFFFFFFFFFFFF
        return format(h, '016x')


# Gestor de claves RSA

class RSAKeyManager:
    @staticmethod
    def generate(bits=2048) -> KeyPair:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pub = priv.public_key()
        return KeyPair(priv, pub)

    @staticmethod
    def save_private(key, path: str):
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        open(path, "wb").write(pem)

    @staticmethod
    def save_public(key, path: str):
        pem = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        open(path, "wb").write(pem)

    @staticmethod
    def load_private(path: str) -> KeyPair:
        data = open(path, "rb").read()
        priv = serialization.load_pem_private_key(data, password=None)
        pub = priv.public_key()
        return KeyPair(priv, pub)

    @staticmethod
    def load_public(path: str):
        data = open(path, "rb").read()
        return serialization.load_pem_public_key(data)


# Cifrado híbrido (RSA + AES)

class HybridCipher:
    @staticmethod
    def encrypt(message: MessageNode, public_key) -> bytes:
        aes_key = AESGCM.generate_key(bit_length=256)
        aes = AESGCM(aes_key)
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, message.content, None)
        enc_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        package = {
            "filename": message.filename or "mensaje.txt",
            "enc_key": base64.b64encode(enc_key).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()
        }
        return json.dumps(package).encode()

    @staticmethod
    def decrypt(package_bytes: bytes, private_key) -> MessageNode:
        p = json.loads(package_bytes.decode())
        enc_key = base64.b64decode(p["enc_key"])
        nonce = base64.b64decode(p["nonce"])
        ct = base64.b64decode(p["ciphertext"])
        aes_key = private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        aes = AESGCM(aes_key)
        plain = aes.decrypt(nonce, ct, None)
        return MessageNode(plain, p.get("filename"))


 #Firma digital

class DigitalSignature:
    @staticmethod
    def sign(message: bytes, private_key) -> SignatureNode:
        sig = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return SignatureNode(data=message, signature=sig, valid=True)

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key) -> bool:
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
