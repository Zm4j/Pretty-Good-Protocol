import base64
import glob
import math
import os
import rsa
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_keys(list_k):
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=int(list_k[2])
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

    with open('Keys/' + list_k[0], 'wb') as f:
        f.write(private_pem)
        f.write(public_pem)


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
                    if "#TIME" in line: data_row[0] = line[6:]
                    if "#SIZE" in line: data_row[-2] = line[6:]
                    if "#USER" in line: data_row[-1] = line[6:]
                    if "END" in line: row_mode = 0
                    if row_mode == 1: data_row[2] += line
                    if row_mode == 2: data_row[3] += line
                    if "BEGIN PUBLIC KEY" in line: row_mode = 1
                    if "BEGIN RSA PRIVATE KEY" in line: row_mode = 2

                data_row[1] = data_row[2][-8:]
            if (filter_user is None or filter_user == data_row[-1]) and (filter_id is None or filter_id == data_row[1]):
                public_key_data.append([data_row[0], data_row[1], data_row[2], data_row[-2], data_row[-1]])

                if data_row[3] != "":
                    private_key_data.append([data_row[0], data_row[1], data_row[2], data_row[3], data_row[-2], data_row[-1]])

    if not filter_private:
        return public_key_data
    return private_key_data


def decrypt_message(file_name):
    file = open(file_name, "rb")
    file_stat = os.stat(file_name)

    PK_ID = file.read(8).decode('utf8')

    public_key_data = get_keys_from_files("./Keys", filter_id=PK_ID)
    print(public_key_data[0])
    PK_SIZE = int(public_key_data[0][3])

    PUBLIC_KEY = public_key_data[0][2]

    ENC_KS = file.read(PK_SIZE//8)


def write_in_bianry_file():
    file = open("output.bin", "wb")

    Pu_ID = 'PQIDAQAB'

    private_key_data = get_keys_from_files("./Keys", filter_id=Pu_ID, filter_private=True)
    print(private_key_data[0])
    PK_SIZE = int(private_key_data[0][4])

    PRIVATE_KEY = private_key_data[0][3]

    file.write(Pu_ID.encode('utf8'))
