import glob
import os
import zlib
from datetime import datetime
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import numpy as np
from additional_stuff import *


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


def radix64_add_pgp_headers(encoded_data):
    header = "-----BEGIN PGP MESSAGE-----\n"
    footer = "\n-----END PGP MESSAGE-----"
    return header + encoded_data.decode('ascii') + footer


def radix64_encode(data):
    encoded_data = base64.b64encode(data)
    pgp_message = radix64_add_pgp_headers(encoded_data)
    return pgp_message


def radix64_decode(encoded_data):
    decoded_data = base64.b64decode(
        encoded_data[len("-----BEGIN PGP MESSAGE-----\n"):-len("\n-----END PGP MESSAGE-----")])
    return decoded_data


def zip_compress_data(data):
    compressed_data = zlib.compress(data)
    return compressed_data


def zip_decompress_data(data):
    decompressed_data = zlib.decompress(data)
    return decompressed_data


def AES128_encryption(message, key):
    message += b'\x00'*15  # padding

    key_list = AES128_generate_keys(key[:16])  # get key for AES rounds

    encrypted_message = b""
    # doing iterations with blocks size 128 bits
    for block_num in range(16, len(message), 16):
        block = np.array([message[block_num-16: block_num][i] for i in range(16)])

        # transform block in matrix by columns
        block = block.reshape((4, 4), order='F')

        block = AES128_add_round_key(block, key_list[0])

        for round_num in range(10):
            block = AES128_substitute(block)
            block = AES128_shift_rows(block)
            if round_num < 9:
                block = AES128_mix_columns(block)

            block = AES128_add_round_key(block, key_list[1+round_num])

        for i in range(4):
            for j in range(4):
                encrypted_message += int(block[j][i]).to_bytes(1, byteorder='big')

    return encrypted_message


def AES128_decryption(encrypted_message, key):

    key_list = AES128_generate_keys(key[:16])  # get key for AES rounds

    message = b""
    # doing iterations with blocks size 128 bits
    for block_num in range(16, len(encrypted_message), 16):
        block = np.array([encrypted_message[block_num - 16: block_num][i] for i in range(16)])

        # transform block in matrix by columns
        block = block.reshape((4, 4), order='F')

        block = AES128_add_round_key(block, key_list[10])

        for round_num in range(10):
            block = AES128_inverse_shift_rows(block)
            block = AES128_inverse_substitute(block)
            block = AES128_add_round_key(block, key_list[9 - round_num])

            if round_num < 9:
                block = AES128_inverse_mix_columns(block)

        for i in range(4):
            for j in range(4):
                message += int(block[j][i]).to_bytes(1, byteorder='big')

    return message


# TODO########################################################################################


def generate_keys(list_k):
    # Generate private key
    password = hashlib.sha1(list_k[3].encode('utf-8')).hexdigest()

    private_key, public_key = rsa_generate_key_pair(int(list_k[2]))
    current_timestamp = datetime.now()

    private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())
    public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    #print(private_key)
    private_key = private_key[len('-----BEGIN RSA PRIVATE KEY-----\n'):-len('-----END RSA PRIVATE KEY-----\n')]
    #print(private_key)
    enc_private_key = AES128_encryption(private_key, bytes.fromhex(password)[:16])
    #print(enc_private_key)
    enc_private_key = b'-----BEGIN RSA PRIVATE KEY-----\n' + enc_private_key + b'-----END RSA PRIVATE KEY-----\n'
    #print(enc_private_key)

    with open('Keys/' + list_k[0], 'wb') as f:
        f.write(enc_private_key)
        f.write(public_key)
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

            with open(file_path, 'rb') as file:
                content = file.read().decode('utf8', errors='replace').split('\n')
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


def authentication():
    message = "This is a secret message."
    hash_hex = hashlib.sha1(message.encode('utf-8')).hexdigest()

    print(f"SHA-1 hash: {hash_hex}")


# TODO#########################################################################


def encrypt_message(file_name, message, list_modes):
    message = message.encode('utf-8')

    if list_modes[1]:
        while True:
            pass

    if list_modes[2]:  # zip
        message = zip_compress_data(message)

    if list_modes[3]:  # radix
        message = radix64_encode(message)

    with open(file_name, 'wb') as f:
        f.write(message)


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

