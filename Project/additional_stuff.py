import numpy as np

S_BOX = [
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]


def radix64_add_pgp_headers(encoded_data):
    header = "-----BEGIN PGP MESSAGE-----\n"
    footer = "\n-----END PGP MESSAGE-----"
    return header + encoded_data.decode('ascii') + footer


def AES128_g(w, i):
    Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    w1 = np.array([S_BOX[w[1] >> 4][w[1] & 0x0F] ^ Rcon[i],
                  S_BOX[w[2] >> 4][w[2] & 0x0F],
                  S_BOX[w[3] >> 4][w[3] & 0x0F],
                  S_BOX[w[0] >> 4][w[0] & 0x0F]])
    return w1


def AES128_generate_keys(in_key):
    in_key = [in_key[i] for i in range(16)]
    w = (np.array(in_key)).reshape((4, 4), order='F')

    key_list = [w]
    for i in range(10):
        new_key = []
        g = AES128_g(w[3], i)
        new_key.append([(w[0][j] ^ g[j]) for j in range(4)])
        new_key.append([(w[1][j] ^ new_key[0][j]) for j in range(4)])
        new_key.append([(w[2][j] ^ new_key[1][j]) for j in range(4)])
        new_key.append([(w[3][j] ^ new_key[2][j]) for j in range(4)])
        key_list.append(np.array(new_key).reshape((4, 4)))
        w = new_key

    return key_list


def AES128_add_round_key(block, key):
    return np.bitwise_xor(block, key)


def AES128_substitute(block):
    sub_block = [S_BOX[block[i//4][i % 4] >> 4][block[i//4][i % 4] & 0x0F] for i in range(16)]
    return (np.array(sub_block)).reshape((4, 4))


def AES128_inverse_substitute(block):
    s_box_arr = [item for sublist in S_BOX for item in sublist]

    inv_s_box = [0] * 256
    for i in range(256):
        inv_s_box[s_box_arr[i]] = i

    INV_S_BOX = np.array(inv_s_box).reshape(16, 16)

    sub_block = [INV_S_BOX[block[i//4][i % 4] >> 4][block[i//4][i % 4] & 0x0F] for i in range(16)]
    return (np.array(sub_block)).reshape((4, 4))


def AES128_shift_rows(block):
    shifted = [block[0][0], block[0][1], block[0][2], block[0][3],
               block[1][1], block[1][2], block[1][3], block[1][0],
               block[2][2], block[2][3], block[2][0], block[2][1],
               block[3][3], block[3][0], block[3][1], block[3][2]]

    return (np.array(shifted)).reshape((4, 4))


def AES128_inverse_shift_rows(block):
    shifted = [block[0][0], block[0][1], block[0][2], block[0][3],
               block[1][3], block[1][0], block[1][1], block[1][2],
               block[2][2], block[2][3], block[2][0], block[2][1],
               block[3][1], block[3][2], block[3][3], block[3][0]]

    return (np.array(shifted)).reshape((4, 4))


def AES128_mix_columns(block):
    C = [[2, 3, 1, 1],
         [1, 2, 3, 1],
         [1, 1, 2, 3],
         [3, 1, 1, 2]]

    block = np.array([item for sublist in block for item in sublist])

    block_t = block.reshape((4, 4), order='F')

    rez = []

    for c_i in C:
        for b_i in block_t:

            elem = 0
            for i in range(4):
                if c_i[i] == 1:
                    elem ^= b_i[i]
                elif c_i[i] == 2:
                    if b_i[i] & 0x80:
                        elem ^= (b_i[i] << 1) ^ 0x11B
                    else:
                        elem ^= (b_i[i] << 1)
                else:
                    if b_i[i] & 0x80:
                        elem ^= (b_i[i] << 1) ^ 0x11B ^ b_i[i]
                    else:
                        elem ^= (b_i[i] << 1) ^ b_i[i]

            rez.append(elem)

    rez = (np.array(rez)).reshape((4, 4))

    return rez


def AES128_inverse_mix_columns(block):
    C_inv = [[14, 11, 13, 9],
         [9, 14, 11, 13],
         [13, 9, 14, 11],
         [11, 13, 9, 14]]

    block = np.array([item for sublist in block for item in sublist])

    block_t = block.reshape((4, 4), order='F')

    rez = []

    for c_i in C_inv:
        for b_i in block_t:
            elem = 0
            for i in range(4):
                if c_i[i] == 0x09:
                    elem ^= multiply_GF(0x09, b_i[i])
                elif c_i[i] == 0x0b:
                    elem ^= multiply_GF(0x0b, b_i[i])
                elif c_i[i] == 0x0d:
                    elem ^= multiply_GF(0x0d, b_i[i])
                elif c_i[i] == 0x0e:
                    elem ^= multiply_GF(0x0e, b_i[i])
            rez.append(elem)

    rez = (np.array(rez)).reshape((4, 4))
    return rez

def multiply_GF(a, b):
    # Multiply two numbers in GF(2^8)
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x11b  # irreducible polynomial x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p