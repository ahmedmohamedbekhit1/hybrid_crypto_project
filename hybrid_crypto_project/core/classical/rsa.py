"""RSA-OAEP primitives for wrapping and unwrapping AES keys."""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keypair(key_size: int = 3072) -> tuple[bytes, bytes]:
    """Generate a fresh RSA keypair and return (private_pem, public_pem)."""
    if key_size < 3072:
        raise ValueError("RSA key size must be at least 3072 bits")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def rsa_wrap_key(public_pem: bytes, symmetric_key: bytes) -> bytes:
    """Wrap a symmetric key with RSA-OAEP-SHA256."""
    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Provided public key is not RSA")
    return public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_unwrap_key(private_pem: bytes, wrapped_key: bytes) -> bytes:
    """Unwrap a symmetric key with RSA-OAEP-SHA256."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("Provided private key is not RSA")
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
