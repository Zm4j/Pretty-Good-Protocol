from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys(listK):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(listK[2])
    )
    # Generate public key from the private key
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
        f.write(public_pem)




