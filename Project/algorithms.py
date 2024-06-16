import glob
import os
import zlib
from datetime import datetime
import hashlib
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import numpy as np
from additional_stuff import *

import secrets


def rsa_generate_key_pair(key_size):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt_message(message, public_key):
    # Calculate the maximum message size for the given key size and padding
    key_size_bytes = (public_key.key_size + 7) // 8
    max_message_size = key_size_bytes - 2 * hashes.SHA256().digest_size - 2
    if len(message) > max_message_size:
        raise ValueError("Message is too long for the given key size")

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
        hashes.SHA1()
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
            hashes.SHA1()
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
    return encoded_data


def radix64_decode(encoded_data):
    decoded_data = base64.b64decode(
        encoded_data)
    return decoded_data


def zip_compress_data(data):
    compressed_data = zlib.compress(data)
    return compressed_data


def zip_decompress_data(data):
    decompressed_data = zlib.decompress(data)
    return decompressed_data


def AES128_encryption(message, key):
    message += b'\x00' * 15  # padding

    key_list = AES128_generate_keys(key[:16])  # get key for AES rounds

    encrypted_message = b""
    # doing iterations with blocks size 128 bits
    for block_num in range(16, len(message), 16):
        block = np.array([message[block_num - 16: block_num][i] for i in range(16)])

        # transform block in matrix by columns
        block = block.reshape((4, 4), order='F')

        block = AES128_add_round_key(block, key_list[0])

        for round_num in range(10):
            block = AES128_substitute(block)
            block = AES128_shift_rows(block)
            if round_num < 9:
                block = AES128_mix_columns(block)

            block = AES128_add_round_key(block, key_list[1 + round_num])

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
                if block_num + 16 >= len(encrypted_message) and int(block[j][i]) == 0:
                    continue
                message += int(block[j][i]).to_bytes(1, byteorder='big')

    return message


def DES_encryption(block, key):  # PROSLEDJUJU SE HEX VREDNOSTI !!!!
    block = bitarray(from_hex_to_binary(block))
    key = bitarray(from_hex_to_binary(key))

    key = key[0:64]
    while len(block) < 64:
        block += "0"

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

    ciphertext_hex = hex(int(ciphertext_string, 2))[2:]
    if len(ciphertext_hex) < 16:
        append_value = "0"
        ciphertext_hex = append_value + str(ciphertext_hex)
    return ciphertext_hex


def DES_decryption(block, key):  # PROSLEDJUJU SE HEX VREDNOSTI !!!!
    block = bitarray(from_hex_to_binary(block))
    key = bitarray(from_hex_to_binary(key))

    key = key[0:64]
    while len(block) < 64:
        block += "0"

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

    ciphertext_hex = hex(int(ciphertext_string, 2))[2:]
    if len(ciphertext_hex) < 16:
        append_value = "0"
        ciphertext_hex = append_value + str(ciphertext_hex)
    return ciphertext_hex


def TripleDES_encr(message, s1, s2):
    return DES_encryption(DES_decryption(DES_encryption(message, s1), s2), s1)


def TripleDES_decr(message, s1, s2):
    return DES_decryption(DES_encryption(DES_decryption(message, s1), s2), s1)


# TODO########################################################################################


def generate_keys(list_k):
    # Generate private key
    password = hashlib.sha1(list_k[3].encode('utf-8')).hexdigest()

    current_timestamp = datetime.now()
    private_key, public_key = rsa_generate_key_pair(int(list_k[2]))

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # private_key = private_key[len('-----BEGIN RSA PRIVATE KEY-----\n'):-len('-----END RSA PRIVATE KEY-----\n')]
    enc_private_key = AES128_encryption(private_pem, bytes.fromhex(password)[:16])
    enc_private_key = b'-----BEGIN RSA PRIVATE KEY-----\n' + enc_private_key + b'\n-----END RSA PRIVATE KEY-----\n'
    print(enc_private_key.decode('utf8', errors='replace'))

    with open('Keys/' + list_k[0] + '.pem', 'wb') as f:
        f.write(enc_private_key)
        f.write(public_pem)
        f.write(("#TIME " + str(current_timestamp) + "\n").encode('utf-8'))
        f.write(("#USER " + str(list_k[1]) + "\n").encode('utf-8'))
        f.write(("#SIZE " + str(list_k[2]) + "\n").encode('utf-8'))
        # OPCIONO CUVA SE LOZINKA ISTO RADI PROVERE PRI TRAZENJU PRIVATNOG KLJUCA
        f.write(("#PASS " + str(list_k[3])).encode('utf-8'))


def get_keys_from_files(dir_path, filter_user=None, filter_id=None, filter_private=False):
    public_key_data = []
    private_key_data = []

    files = glob.glob(os.path.join(dir_path, '*'))

    for file_path in files:
        if os.path.isfile(file_path):
            data_row = [b"00:00:00", b"", b"", b"", b"", b"", b"example@gmail.com"]

            with open(file_path, 'rb') as file:
                content = file.read().split(b'\n')
                row_mode = 0
                for line in content:
                    if b"#TIME" in line:
                        data_row[0] = line[6:]
                    if b"#USER" in line:
                        data_row[-1] = line[6:]
                    if b"#SIZE" in line:
                        data_row[-2] = line[6:]
                    if b"#PASS" in line:
                        data_row[-3] = line[6:]
                    if b"BEGIN PUBLIC KEY" in line:
                        row_mode = 1
                    if b"BEGIN RSA PRIVATE KEY" in line:
                        row_mode = 2
                    if row_mode == 1:
                        data_row[2] += line + b'\n'
                    if row_mode == 2:
                        data_row[3] += line + b'\n'
                    if b"END" in line:
                        row_mode = 0

                data_row[1] = data_row[2][-8 - len('\n-----END PUBLIC KEY-----\n'):-len('\n-----END PUBLIC KEY-----\n')]
            if (filter_user is None or filter_user == data_row[-1]) and (filter_id is None or filter_id == data_row[1]):
                public_key_data.append(
                    [data_row[0], data_row[1], data_row[2], data_row[-2], data_row[-1], data_row[-3]])

                if data_row[3] != "":
                    private_key_data.append(
                        [data_row[0], data_row[1], data_row[2], data_row[3], data_row[-2], data_row[-1], data_row[-3]])

    if not filter_private:
        return public_key_data
    return private_key_data


def authentication():
    message = "This is a secret message."
    hash_hex = hashlib.sha1(message.encode('utf-8')).hexdigest()

    print(f"SHA-1 hash: {hash_hex}")


# TODO#########################################################################


def encrypt_message(file_name, message, list_modes, enc_ID, ver_ID, alg_num, b_enc_key, b_ver_key):
    message = message.encode('utf-8')
    """
    print(file_name)
    print(message)
    print(list_modes)
    print(enc_ID)
    print(ver_ID)
    print(alg_num)
    print(b_enc_key)
    print(b_ver_key)
    """
    mode = [0, 0, 0, 0]

    if list_modes[1]:  # authentication
        # H = hashlib.sha1(message)

        ver_key = serialization.load_pem_private_key(
            b_ver_key,
            password=None,
            backend=default_backend()
        )

        # sifrujemo koriscenjuem RSA alg
        signature = rsa_sign_message(message, ver_key)

        concatenatedmsg = ver_ID.encode('utf-8') + signature + message

        message = concatenatedmsg
        mode[1] = 1
        print("Message after authentication: ", message)

    if list_modes[2]:  # zip
        message = zip_compress_data(message)
        mode[2] = 1
        print("Message after zip: ", message)

    if list_modes[0]:  # privacy

        enc_key = serialization.load_pem_public_key(
            b_enc_key,
            backend=default_backend()
        )
        #proveravamo koji je od algoritama izabran
        if alg_num == 0:
            # 3DES
            session_key1 = secrets.token_bytes(128)
            integer_value = int.from_bytes(session_key1, byteorder='big')
            session_key1 = hex(integer_value)[2:]
            session_key1 = session_key1[0:32]
            #print("Session Key 1:", session_key1)

            session_key2 = secrets.token_bytes(128)
            integer_value = int.from_bytes(session_key2, byteorder='big')
            session_key2 = hex(integer_value)[2:]
            session_key2 = session_key2[0:32]
            #print("Session Key 2:", session_key2)

            integer_value = int.from_bytes(message, byteorder='big')
            message = str(hex(integer_value)[2:])

            blocks = []
            for i in range(0, len(message), 16):
                blocks.append(message[i:i + 16])

            ciphertext = ""
            #print(blocks)
            for i in range(len(blocks)):
                ciphertext += TripleDES_encr(blocks[i], session_key1, session_key2)

            """
            blocks_decr = []
            for i in range(0, len(c), 16):
                blocks_decr.append(c[i:i+16])

            m = ""
            for i in range(len(blocks_decr)):
                m += TripleDES_decr(blocks_decr[i], session_key1, session_key2)
            print(m)
            """
            # enkripcija sesijskog kljuca

            ciphertext = bytes.fromhex(ciphertext)

            encrypted_sk1 = rsa_encrypt_message(bytes.fromhex(session_key1), enc_key)
            encrypted_sk2 = rsa_encrypt_message(bytes.fromhex(session_key2), enc_key)

            ciphertext = b'\x00' + enc_ID.encode('utf-8') + encrypted_sk1 + encrypted_sk2 + ciphertext

            message = ciphertext

        else:
            # AES128
            session_key1 = secrets.token_bytes(128)
            session_key1 = session_key1[0:16]

            ciphertext = AES128_encryption(message, session_key1)

            encrypted_sk1 = rsa_encrypt_message(session_key1, enc_key)
            print("AES session key: ", encrypted_sk1)
            # print(len(encrypted_sk1))
            ciphertext = b'\x01' + enc_ID.encode('utf-8') + encrypted_sk1 + ciphertext

            message = ciphertext

        mode[0] = 1
        print("Message after privacy: ", message)

    if list_modes[3]:  # radix
        message = radix64_encode(message)
        mode[3] = 1
        print("Message after radix: ", message)

    str_mode = ""
    for i in mode:
        str_mode += str(i)

    message = str_mode.encode('utf-8') + message
    with open(file_name, 'wb') as f:
        f.write(message)


def decrypt_message(file_name, password):
    """
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
    """
    file = open(file_name, "rb")

    file_content = file.read()

    mode = file_content[:4].decode('utf-8')

    message = file_content[4:]
    print(type(mode))
    # print(mode)
    # print(message)
    print("Message before radix: ", message)
    if mode[3]:  # radix
        message = radix64_decode(message)
        print("Message before privacy : ", message)

    if mode[0]:  # privacy
        code = message[0]
        print(code)
        if code == 0:
            # 3DES
            pass
        elif code == 1:
            # AES128
            enc_ID = message[1:9]
            session_key1_enc = message[9:137]
            print(enc_ID)
            print(session_key1_enc)

            enc_key = get_keys_from_files("./Keys", filter_id=enc_ID, filter_private=True)
            print()
            private_key_enc = enc_key[0][3][
                          len("-----BEGIN RSA PRIVATE KEY-----\n"):-len("\n-----END RSA PRIVATE KEY-----\n")]
            print(private_key_enc)

            password = hashlib.sha1(password.encode('utf-8')).hexdigest()
            private_key_enc = AES128_decryption(private_key_enc, bytes.fromhex(password)[:16])
            print(private_key_enc)
            # encrypted_sk1 = rsa_encrypt_message(session_key1, enc_key)

            private_key = serialization.load_pem_private_key(
                private_key_enc,
                password=None,
                backend=default_backend()
            )
            session_key1_decr = rsa_decrypt_message(session_key1_enc, private_key)

            print(session_key1_decr)

    if mode[2]:  # zip
        pass

    if mode[1]:  # authentication
        pass
