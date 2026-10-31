
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from schemas import ReceiptVerifier


# Generate a temporary valid Ed25519 key pair
private_key = Ed25519PrivateKey.generate()

public_bytes = private_key.public_key().public_bytes(
    Encoding.Raw,
    PublicFormat.Raw
)

public_x = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("ascii")

valid_jwk = {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": public_x
}

# Test valid key
valid = ReceiptVerifier(
    algorithm="Ed25519",
    publicKeyJwk=valid_jwk
)

print("Valid key accepted:", valid.algorithm == "Ed25519")

# Test invalid key
try:
    ReceiptVerifier(
        algorithm="Ed25519",
        publicKeyJwk={
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "invalid-key"
        }
    )
    print("ERROR: Invalid key was accepted")
except Exception:
    print("Invalid key rejected: True")
