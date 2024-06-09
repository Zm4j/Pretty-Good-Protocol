import glob
import os
from datetime import datetime
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def rsa_generate_key_pair(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt_message(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


def rsa_decrypt_message(encrypted_message, private_key):
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message


def rsa_sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def rsa_verify_signature(message, signature, public_key):
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
    except Exception as e:
        print(f"Verification failed: {e}")
        return False


def generate_keys(list_k):
    # Generate private key

    private_key, public_key = rsa_generate_key_pair(int(list_k[2]))

    # TODO - POTENCIJALNA IZMENA
    # Get the current date and time
    current_timestamp = datetime.now()

    with open('Keys/' + list_k[0], 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        f.write(("#TIME " + str(current_timestamp) + "\n").encode('utf-8'))
        f.write(("#USER " + str(list_k[1]) + "\n").encode('utf-8'))
        f.write(("#SIZE " + str(list_k[2]) + "\n").encode('utf-8'))


def get_keys_from_files(dir_path, filter_user=None, filter_id=None, filter_private=False):
    public_key_data = []
    private_key_data = []

    files = glob.glob(os.path.join(dir_path, '*'))

    for file_path in files:
        if os.path.isfile(file_path):
            data_row = ["00:00:00", "", "", "", "", "example@gmail.com"]

            with open(file_path, 'r') as file:
                content = file.read().split('\n')
                row_mode = 0
                for line in content:
                    if "#TIME" in line:
                        data_row[0] = line[6:]
                    if "#SIZE" in line:
                        data_row[-2] = line[6:]
                    if "#USER" in line:
                        data_row[-1] = line[6:]
                    if "END" in line:
                        row_mode = 0
                    if row_mode == 1:
                        data_row[2] += line
                    if row_mode == 2:
                        data_row[3] += line
                    if "BEGIN PUBLIC KEY" in line:
                        row_mode = 1
                    if "BEGIN RSA PRIVATE KEY" in line:
                        row_mode = 2

                data_row[1] = data_row[2][-8:]
            if (filter_user is None or filter_user == data_row[-1]) and (filter_id is None or filter_id == data_row[1]):
                public_key_data.append([data_row[0], data_row[1], data_row[2], data_row[-2], data_row[-1]])

                if data_row[3] != "":
                    private_key_data.append(
                        [data_row[0], data_row[1], data_row[2], data_row[3], data_row[-2], data_row[-1]])

    if not filter_private:
        return public_key_data
    return private_key_data


# TODO########################################################################################


def encrypt_message(file_name):
    pass


# TODO
def authentication():
    message = "This is a secret message."
    hash_hex = hashlib.sha1(message.encode('utf-8')).hexdigest()

    print(f"SHA-1 hash: {hash_hex}")


def radix64_encode(data):
    encoded_data = base64.b64encode(data)
    return encoded_data


def radix64_decode(encoded_data):
    decoded_data = base64.b64decode(encoded_data)
    return decoded_data


def crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def add_pgp_headers(encoded_data):
    header = "-----BEGIN PGP MESSAGE-----\n"
    footer = "\n-----END PGP MESSAGE-----"
    return header + encoded_data.decode('ascii') + footer


def radix_64():
    # Original data
    data = b'This is a secret message.'

    # Encode data
    encoded_data = radix64_encode(data)

    # Compute CRC-24
    crc_value = crc24(data)
    crc_bytes = crc_value.to_bytes(3, byteorder='big')

    # Append CRC to the encoded data
    encoded_with_crc = encoded_data + b'\n=' + base64.b64encode(crc_bytes)

    # Add headers and footers
    pgp_message = add_pgp_headers(encoded_with_crc)

    print(pgp_message)


# TODO#########################################################################
def decrypt_message(file_name):
    print(file_name)
    file = open(file_name, "rb")
    file_stat = os.stat(file_name)

    PK_ID = file.read(8).decode('utf8')
    print(PK_ID)
    public_key_data = get_keys_from_files("./Keys", filter_id=PK_ID)
    print(public_key_data[0])
    PK_SIZE = int(public_key_data[0][3])

    PUBLIC_KEY = public_key_data[0][2]

    ENC_KS = file.read(PK_SIZE // 8)
