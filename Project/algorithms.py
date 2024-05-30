import glob
import os
import time
from datetime import datetime
import gmpy2
from gmpy2 import mpz, powmod, gcd, invert


def key_to_bytes(key):
    e_or_d, n = key
    e_or_d_bytes = e_or_d.digits(16).encode()  # Serialize as hexadecimal string
    n_bytes = n.digits(16).encode()

    return e_or_d_bytes, n_bytes


def bytes_to_key(e_or_d_bytes, n_bytes):
    e_or_d = mpz(e_or_d_bytes.decode(), 16)  # Deserialize from hexadecimal string
    n = mpz(n_bytes.decode(), 16)

    return e_or_d, n


def generate_rsa_keys(bit_size=1024):
    seed = int(time.time() * 1000)
    state = gmpy2.random_state(seed)
    p = gmpy2.next_prime(gmpy2.mpz_rrandomb(state, bit_size // 2))
    q = gmpy2.next_prime(gmpy2.mpz_rrandomb(state, bit_size // 2))

    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = mpz(65537)
    if gcd(e, phi_n) != 1:
        e = gmpy2.next_prime(e)
    d = invert(e, phi_n)

    return (e, n), (d, n)


def encrypt_rsa(message, public_key):
    e, n = public_key
    m = mpz(message)
    c = powmod(m, e, n)
    return c


def decrypt_rsa(ciphertext, private_key):
    d, n = private_key
    m = powmod(ciphertext, d, n)
    return m


def generate_keys(list_k):
    # Generate private key

    public_key, private_key = generate_rsa_keys(int(list_k[2]))
    public_key_bytes = key_to_bytes(public_key)
    private_key_bytes = key_to_bytes(private_key)
    print(public_key_bytes)
    print(private_key_bytes)

    #TODO - POTENCIJALNA IZMENA
    # Get the current date and time
    current_timestamp = datetime.now()

    # Print the current timestamp
    print(current_timestamp)

    print("GENERATE KEY: ", list_k)

    line_time = "#TIME " + str(current_timestamp) + "\n"
    line_user = "#USER " + str(list_k[1]) + "\n"
    line_size = "#SIZE " + str(list_k[2]) + "\n"

    """
    string_data = "Hello, this is a string."
    file.write(string_data.encode('utf-8'))
    """
    with open('Keys/' + list_k[0], 'wb') as f:
        f.write(line_time.encode('utf-8'))
        f.write(line_user.encode('utf-8'))
        f.write(line_size.encode('utf-8'))
        f.write(b"-----BEGIN PUBLIC KEY-----\n")
        f.write(public_key_bytes[0] + b'-' + public_key_bytes[1] + b'\n')
        f.write(b"-----END PUBLIC KEY-----\n")
        f.write(b"-----BEGIN RSA PRIVATE KEY-----\n")
        f.write(private_key_bytes[0] + b'-' + private_key_bytes[1] + b'\n')
        f.write(b"-----END RSA PRIVATE KEY-----\n")


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
    print(file_name)
    file = open(file_name, "rb")
    file_stat = os.stat(file_name)

    PK_ID = file.read(8).decode('utf8')
    print(PK_ID)
    public_key_data = get_keys_from_files("./Keys", filter_id=PK_ID)
    print(public_key_data[0])
    PK_SIZE = int(public_key_data[0][3])

    PUBLIC_KEY = public_key_data[0][2]

    ENC_KS = file.read(PK_SIZE//8)


def write_in_bianary_file():
    file = open("output.bin", "wb")

    Pu_ID = 'PQIDAQAB'

    private_key_data = get_keys_from_files("./Keys", filter_id=Pu_ID, filter_private=True)
    print(private_key_data[0])
    PK_SIZE = int(private_key_data[0][4])

    PRIVATE_KEY = private_key_data[0][3]

    file.write(Pu_ID.encode('utf8'))
