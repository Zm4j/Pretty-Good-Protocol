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


def zip_decompress_data(compressed_data):
    try:
        decompressed_data = zlib.decompress(compressed_data)
        return decompressed_data
    except zlib.error as e:
        print(f"Decompression error: {e}")
        return None


def AES128_encryption(message, key):
    message += b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

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
    for block_num in range(16, len(encrypted_message)+1, 16):
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
                #if block_num + 16 >= len(encrypted_message) and int(block[j][i]) == 0:
                    #continue
                # OVO NE SME DA SOTJI GORE AL JBG, TREBA KORISNIK DA BRISE \x00 viskove
                message += int(block[j][i]).to_bytes(1, byteorder='big')

    return message


def DES_encryption(block, key):  # PROSLEDJUJU SE HEX VREDNOSTI !!!!
    #print(block)
    block = bytes_to_bitarray(block)

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

    ciphertext_hex = int(ciphertext_string, 2)
    ciphertext_hex = f"{ciphertext_hex:0{16}x}"

    return bytes.fromhex(ciphertext_hex)


def DES_decryption(block, key):  # PROSLEDJUJU SE HEX VREDNOSTI !!!!
    block = bytes_to_bitarray(block)
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

    ciphertext_hex = int(ciphertext_string, 2)
    # if len(ciphertext_hex) < 16:
    #     append_value = "0"
    #     ciphertext_hex = append_value + str(ciphertext_hex)

    ciphertext_hex = f"{ciphertext_hex:0{16}x}"
    return bytes.fromhex(ciphertext_hex)


def TripleDES_encr(message, s1, s2):
    integer_value = int.from_bytes(s1, byteorder='big')
    s1 = hex(integer_value)[2:]
    integer_value = int.from_bytes(s2, byteorder='big')
    s2 = hex(integer_value)[2:]

    blocks = []
    for i in range(0, len(message)+1, 8):
        m = (message[i:i+8] + b'\x00\x00\x00\x00\x00\x00\x00\x00')[0:8]
        blocks.append(m)

    ciphertext = b""
    for i in range(len(blocks)):
        ciphertext += DES_encryption(DES_decryption(DES_encryption(blocks[i], s1), s2), s1)

    return ciphertext


def TripleDES_decr(message, s1, s2):
    integer_value = int.from_bytes(s1, byteorder='big')
    s1 = hex(integer_value)[2:]
    integer_value = int.from_bytes(s2, byteorder='big')
    s2 = hex(integer_value)[2:]

    blocks_decr = []
    for i in range(0, len(message)+1, 8):
        blocks_decr.append(message[i:i + 8])

    m = b""
    for i in range(len(blocks_decr)):
        m += DES_decryption(DES_encryption(DES_decryption(blocks_decr[i], s1), s2), s1)

    return m


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
    mode = [0, 0, 0, 0]

    if list_modes[1]:  # authentication
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

    if list_modes[2]:  # zip
        message = zip_compress_data(message)
        mode[2] = 1

    if list_modes[0]:  # privacy
        message = (255).to_bytes(1, 'big') + len(message).to_bytes(4, 'big') + message


        enc_key = serialization.load_pem_public_key(
            b_enc_key,
            backend=default_backend()
        )
        #proveravamo koji je od algoritama izabran
        if alg_num == 0:
            # 3DES
            session_key1 = secrets.token_bytes(16)
            session_key2 = secrets.token_bytes(16)

            ciphertext = TripleDES_encr(message, session_key1, session_key2)

            encrypted_sk1 = rsa_encrypt_message(session_key1, enc_key)
            encrypted_sk2 = rsa_encrypt_message(session_key2, enc_key)

            ciphertext = b'\x00' + enc_ID.encode('utf-8') + encrypted_sk1 + encrypted_sk2 + ciphertext

            message = ciphertext

        else:
            # AES128
            session_key1 = secrets.token_bytes(16)

            ciphertext = AES128_encryption(message, session_key1)

            encrypted_sk1 = rsa_encrypt_message(session_key1, enc_key)

            ciphertext = b'\x01' + enc_ID.encode('utf-8') + encrypted_sk1 + ciphertext

            message = ciphertext

        mode[0] = 1
        #print("Message after privacy: ", message)

    if list_modes[3]:  # radix
        message = radix64_encode(message)
        mode[3] = 1
        #print("Message after radix: ", message)

    str_mode = ""
    for i in mode:
        str_mode += str(i)

    message = str_mode.encode('utf-8') + message
    with open(file_name, 'wb') as f:
        f.write(message)


def decrypt_message(file_name, password):
    file = open(file_name, "rb")
    file_content = file.read()
    mode = file_content[:4].decode('utf-8')

    message = file_content[4:]
    if mode[3] == '1':  # radix
        message = radix64_decode(message)

    if mode[0] == '1':  # privacy
        code = message[0]
        enc_ID = message[1:9]
        enc_key = get_keys_from_files("./Keys", filter_id=enc_ID, filter_private=True)
        private_key_enc = enc_key[0][3][len("-----BEGIN RSA PRIVATE KEY-----\n"):-len("-----END RSA PRIVATE KEY-----\n")]
        password = hashlib.sha1(password.encode('utf-8')).hexdigest()
        private_key = AES128_decryption(private_key_enc, bytes.fromhex(password)[:16])
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )

        if code == 0:  # 3DES
            session_key1_enc = message[9:137]
            session_key2_enc = message[137:265]

            session_key1_decr = rsa_decrypt_message(session_key1_enc, private_key)
            session_key2_decr = rsa_decrypt_message(session_key2_enc, private_key)
            message = TripleDES_decr(message[265:], session_key1_decr, session_key2_decr)

        elif code == 1:  # AES128
            session_key1_enc = message[9:137]

            session_key1_decr = rsa_decrypt_message(session_key1_enc, private_key)
            message = AES128_decryption(message[137:], session_key1_decr)

        message = message[1:]
        mes_size = int.from_bytes(message[:4], 'big') + 4
        message = message[4:mes_size]

    if mode[2] == '1':  # zip
        message = zip_decompress_data(message)

    if mode[1] == '1':  # authentication
        ver_ID = message[0:8]
        ver_key = get_keys_from_files("./Keys", filter_id=ver_ID,)
        ver_key = ver_key[0][2]

        ver_key = serialization.load_pem_public_key(
            ver_key,
            backend=default_backend()
        )

        signature = message[8:136]
        message = message[136:]
        if rsa_verify_signature(message, signature, ver_key):
            print("MESSAGE IS VERIFIED")
        else:
            print("MESSAGE GOT CORRUPTED")

    print(message)