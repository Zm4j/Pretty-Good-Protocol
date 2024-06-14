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
from bitarray import bitarray
from bitarray.util import ba2int, int2ba

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

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
]

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 3, 12, 5]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

KEY_SHIFTS = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

def permute(block, matrix):
    return [block[i-1] for i in matrix]

def feistel_function(f, left, right):
    return right, [left[i] ^ f[i] for i in range(len(f))]

def xor(value1, value2):
    return [value1[i] ^ value2[i] for i in range(len(value1))]
def sbox_substitution(bits):
    output = []
    for i in range(8):
        block = bits[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        sbox_value = S_BOXES[i][row][col]
        output.extend(int2ba(sbox_value, length=4))
    return output

def f_function(right, subkey):
    expanded_right = permute(right, E)
    xored = xor(expanded_right, subkey)
    substituted = sbox_substitution(xored)
    return permute(substituted, P)

def generate_subkeys(key):
    key = permute(key, PC1)
    C = key[:28]
    D = key[28:]
    subkeys = []
    for shift in KEY_SHIFTS:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        subkeys.append(permute(C + D, PC2))
    return subkeys

def from_hex_to_binary(hex):
    integer_value = int(hex, 16)
    binary_str = bin(integer_value)[2:]
    return binary_str.zfill(len(hex) * 4)

def DES_encryption(block, key): # PROSLEDJUJU SE HEX VREDNOSTI !!!!
    block = bitarray(from_hex_to_binary(block))
    key = bitarray(from_hex_to_binary(key))

    block = permute(block, IP)
    left, right = block[:32], block[32:]

    subkeys = generate_subkeys(key)

    for subkey in subkeys:
        left, right = feistel_function(f_function(right, subkey), left, right)
    block = right + left

    return_value = permute(block, FP)
    ciphertext_string = ""
    for i in return_value:
        ciphertext_string += str(i)
    return hex(int(ciphertext_string, 2))[2:]


def DES_decryption(block, key):  # PROSLEDJUJU SE HEX VREDNOSTI !!!!
    block = bitarray(from_hex_to_binary(block))
    key = bitarray(from_hex_to_binary(key))

    block = permute(block, IP)
    left, right = block[:32], block[32:]

    subkeys = generate_subkeys(key)
    subkeys.reverse()

    for subkey in subkeys:
        left, right = feistel_function(f_function(right, subkey), left, right)
    block = right + left

    return_value = permute(block, FP)
    ciphertext_string = ""
    for i in return_value:
        ciphertext_string += str(i)
    return hex(int(ciphertext_string, 2))[2:]

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

