import sys

import gmpy2 as gmpy2
import pygame as pygame
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from components import *
from algorithms import *

pygame.init()
main_screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("PGP")
GENERATE_KEY_VALUES = []


def set_screen_mod(x):
    global SCREEN_MOD
    SCREEN_MOD = x


def clearscreen():
    main_screen.fill(WHITE)


def handle_events(components, radio_group=[]):
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            pygame.quit()
            sys.exit()
        for component in components:
            if isinstance(component, RadioButton):
                component.handle_event(event, radio_group)
            else:
                component.handle_event(event)


def draw_components(color, components):
    main_screen.fill(color)
    for component in components:
        component.draw(main_screen)


def main():
    clock = pygame.time.Clock()
    return_button = Button(0, 0, BUTTON_WIDTH // 2, BUTTON_HEIGHT // 2, "return", lambda: set_screen_mod(MOD.DEFAULT))

    # components for generate mod
    G1_name = TextBox((WIDTH - BUTTON_WIDTH) // 2, 50, 350, 50)
    G1_email = TextBox((WIDTH - BUTTON_WIDTH) // 2, 150, 350, 50)
    G1_radio_bits = [RadioButton((WIDTH - BUTTON_WIDTH) // 2 + 10, 275, "1024"),
                     RadioButton((WIDTH - BUTTON_WIDTH) // 2 + 110, 275, "2048")]
    G1_password = TextBox((WIDTH - BUTTON_WIDTH) // 2, 350, 350, 50)

    G2_massage = TextBox((WIDTH - BUTTON_WIDTH) // 2-350, 50, 1050, 90)
    G2_file_name = TextBox((WIDTH - BUTTON_WIDTH) // 2-350, 150, 350, 50)
    G2_checkboxes = [CheckBox(200, 300 + i*80, 20, ["TAJNOST", "AUTENTIKACIJA", "KOMPRESIJA", "RADIX64"][i]) for i in range(4)]
    G2_encription_keyID = ""
    G2_verify_keyID = ""
    G2_encryption_key = b""
    G2_verify_key = b""
    G2_select_alg = [RadioButton(WIDTH - 450, 290, "TripleDES"),
                     RadioButton(WIDTH - 450, 330, "AES128")]

    G4_user_id = TextBox(50, HEIGHT-100, 350, 50)
    G4_radio_buttons = [RadioButton(50, 115 + i*20, "") for i in range(30)]
    G4_password = TextBox(WIDTH - 200 - BUTTON_WIDTH, HEIGHT-100, 350, 50)

    while True:
        if SCREEN_MOD == MOD.DEFAULT:
            # TODO brisi sve promenljive, to treba umesto ind=1
            clearscreen()

            components = []
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"Generate Key", lambda: set_screen_mod(MOD.GENERATE)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "View Key Tables",lambda: set_screen_mod(MOD.KEY_TABLE_VIEW)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"Encrypt Message", lambda: set_screen_mod(MOD.ENCRYPT)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 12 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"Decrypt Message", lambda: set_screen_mod(MOD.DECRYPT)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 18 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"TEST", lambda: set_screen_mod(MOD.TEST)))
            draw_components(WHITE, components)
            handle_events(components)

            if G1_name.getText() != '' and G1_email.getText() != '' and (G1_radio_bits[0].is_selected() or G1_radio_bits[1].is_selected()) and G1_password.getText() != '':
                GENERATE_KEY_VALUES.append(G1_name.getText())
                GENERATE_KEY_VALUES.append(G1_email.getText())
                GENERATE_KEY_VALUES.append(G1_radio_bits[0].text if G1_radio_bits[0].is_selected() else G1_radio_bits[1].text)
                GENERATE_KEY_VALUES.append(G1_password.getText())
                generate_keys(GENERATE_KEY_VALUES)


            G1_name.setText("")
            G1_password.setText("")
            G1_radio_bits[0].clear()
            G1_email.setText("")

        elif SCREEN_MOD == MOD.GENERATE:
            # TODO MOD treba da se menja !!!
            components = [return_button]
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, 430, BUTTON_WIDTH, BUTTON_HEIGHT, "add", lambda: set_screen_mod(MOD.DEFAULT)))
            components.append(Label("Name: ", 100, 60))
            components.append(Label("e-mail: ", 100, 160))
            components.append(Label("Bits: ", 100, 260))
            components.append(Label("Password: ", 100, 360))
            components.append(G1_name)
            components.append(G1_email)
            components.append(G1_password)
            components += G1_radio_bits

            draw_components(YELLOW, components)
            handle_events(components, G1_radio_bits)

        elif SCREEN_MOD == MOD.ENCRYPT:
            G4_user_id.setText("")
            for i in G4_radio_buttons: i.clear()

            components = [return_button]
            components.append(Label("Message : ", 100, 60))
            components.append(G2_massage)
            components.append(Label("File name : ", 100, 160))
            components.append(G2_file_name)
            components += G2_checkboxes

            list_modes = [G2_checkboxes[i].isChecked() for i in range(4)]

            if G2_checkboxes[0].isChecked():  # ENCRYPTION
                components += G2_select_alg
                components.append(Button(500, 285, BUTTON_WIDTH, BUTTON_HEIGHT, "SELECT KEY", lambda: set_screen_mod(MOD.SELECT_KEY_E)))
                components.append(Label("not selected" if G2_encription_keyID == "" else "selected  " + G2_encription_keyID, 750, 300))

            if G2_checkboxes[1].isChecked():  # VERIFICATION
                components.append(Button(500, 365, BUTTON_WIDTH, BUTTON_HEIGHT, "SELECT KEY", lambda: set_screen_mod(MOD.SELECT_KEY_V)))
                components.append(Label("not selected" if G2_verify_keyID == "" else "selected  " + G2_verify_keyID, 750, 380))

            #if not((G2_checkboxes[0].isChecked() and G2_encription_keyID == "") and (G2_checkboxes[1].isChecked() and G2_encription_keyID == "")):
            if ((G2_encription_keyID!="" and (G2_select_alg[0].is_selected() or G2_select_alg[1].is_selected())) or not G2_checkboxes[0].isChecked()) and (G2_verify_keyID!="" or not G2_checkboxes[1].isChecked()):
                components.append(Button((WIDTH - BUTTON_WIDTH) // 2, HEIGHT - 150, BUTTON_WIDTH, BUTTON_HEIGHT, "Encrypt",lambda: encrypt_message(G2_file_name.getText(), G2_massage.getText(), list_modes, G2_encription_keyID, G2_verify_keyID, 0 if G2_select_alg[0].is_selected() else 1, G2_encryption_key, G2_verify_key)))

            draw_components(LIGHT_BLUE, components)
            handle_events(components, G2_select_alg)

        elif SCREEN_MOD == MOD.DECRYPT:
            components = [return_button]
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Decript",lambda: decrypt_message('output.bin')))
            draw_components(PURPLE, components)
            handle_events(components)

        elif SCREEN_MOD == MOD.KEY_TABLE_VIEW:
            filter_id = G4_user_id.getText()
            if filter_id == "see_all_keys":
                filter_id = None

            private_key_data = get_keys_from_files("./Keys", filter_private=True, filter_user=filter_id)
            public_key_data = get_keys_from_files("./Keys", filter_user=filter_id)

            components = [return_button, G4_user_id]
            components.append(Label("E-mail", 70, HEIGHT - 140))
            components.append(Label("RSA PRIVATE KEY TABLE", (WIDTH - 300) // 2, 40))
            components.append(Label("RSA PUBLIC KEY TABLE", (WIDTH - 300) // 2, HEIGHT // 2))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 2 * BUTTON_HEIGHT), BUTTON_WIDTH, BUTTON_HEIGHT,"SAVE TABLE",lambda: set_screen_mod(MOD.KEY_TABLE_VIEW)))

            public_key_data_decoded = []
            for row in public_key_data:
                table_row = []
                for index, value in enumerate(row):
                    if index == 2:
                        table_row.append(value.decode('utf8', errors='replace')[len('-----BEGIN PUBLIC KEY-----\n'):])
                    else:
                        table_row.append(value.decode('utf8', errors='replace'))
                public_key_data_decoded.append(table_row)

            private_key_data_decoded = []
            for row in private_key_data:
                table_row = []
                for index, value in enumerate(row):
                    if index == 2:
                        table_row.append(value.decode('utf8', errors='replace')[len('-----BEGIN PUBLIC KEY-----\n'):])
                    elif index == 3:
                        table_row.append(value.decode('utf8', errors='replace')[len('-----BEGIN RSA PRIVATE KEY-----\n'):])
                    else:
                        table_row.append(value.decode('utf8', errors='replace'))
                private_key_data_decoded.append(table_row)

            components.append(Table((WIDTH - 1350) // 2, 80,["Timestamp", "Key ID", "Public Key", "Encrypted Private Key", "Key Size","User ID"], private_key_data_decoded))
            components.append(Table((WIDTH - 1125) // 2, HEIGHT // 2 + 40,["Timestamp", "Key ID", "Public Key", "Key Size", "User ID"], public_key_data_decoded))

            draw_components(WHITE, components)
            handle_events(components)

        elif SCREEN_MOD == MOD.SELECT_KEY_V:
            selected_id = -1
            filter_id = G4_user_id.getText()
            if filter_id == "see_all_keys":
                filter_id = None

            components = [G4_user_id, G4_password]
            components.append(Label("Password is NOT matching" if G2_verify_keyID == "" else "Password is matching", WIDTH - 180 - BUTTON_WIDTH, HEIGHT-140))
            components.append(Label("E-mail", 70, HEIGHT-140))
            components.append(Button(0, 0, BUTTON_WIDTH // 2, BUTTON_HEIGHT // 2, "return", lambda: set_screen_mod(MOD.ENCRYPT)))

            private_key_data = get_keys_from_files("./Keys", filter_private=True, filter_user=filter_id)
            components.append(Label("RSA PRIVATE KEY TABLE", (WIDTH - 300) // 2, 40))

            private_key_data_decoded = []
            for row in private_key_data:
                table_row = []
                for index, value in enumerate(row):
                    if index == 2:
                        table_row.append(value.decode('utf8', errors='replace')[len('-----BEGIN PUBLIC KEY-----\n'):])
                    elif index == 3:
                        table_row.append(
                            value.decode('utf8', errors='replace')[len('-----BEGIN RSA PRIVATE KEY-----\n'):])
                    else:
                        table_row.append(value.decode('utf8', errors='replace'))
                private_key_data_decoded.append(table_row)

            components.append(Table((WIDTH - 1350) // 2, 80, ["Timestamp", "Key ID", "Public Key", "Encrypted Private Key", "Key Size", "User ID"], private_key_data_decoded))
            radio_buttons_temp = G4_radio_buttons[:len(private_key_data)]

            for i in range(len(radio_buttons_temp)):
                if radio_buttons_temp[i].is_selected():
                    selected_id = i

            if selected_id != -1 and G4_password.getText() == private_key_data[selected_id][-1].decode('utf8'):
                G2_verify_keyID = private_key_data[selected_id][1].decode('utf8')
                password = hashlib.sha1(private_key_data[selected_id][-1]).hexdigest()
                G2_verify_key = private_key_data[selected_id][3][len('-----BEGIN RSA PRIVATE KEY-----\n'):-len('-----END RSA PRIVATE KEY-----\n')]
                G2_verify_key = AES128_decryption(G2_verify_key, bytes.fromhex(password)[:16])
                #print(G2_verify_key)
            else:
                G2_verify_keyID = ""
                G2_verify_key = b""

            components += radio_buttons_temp
            draw_components(WHITE, components)
            handle_events(components, G4_radio_buttons)

        elif SCREEN_MOD == MOD.SELECT_KEY_E:
            filter_id = G4_user_id.getText()
            if filter_id == "see_all_keys":
                filter_id = None

            components = [G4_user_id]
            components.append(Label("E-mail", 70, HEIGHT-140))
            components.append(Button(0, 0, BUTTON_WIDTH // 2, BUTTON_HEIGHT // 2, "return", lambda: set_screen_mod(MOD.ENCRYPT)))

            public_key_data = get_keys_from_files("./Keys", filter_user=filter_id)
            components.append(Label("RSA PUBLIC KEY TABLE", (WIDTH - 300) // 2, 40))

            public_key_data_decoded = []
            for row in public_key_data:
                table_row = []
                for index, value in enumerate(row):
                    if index == 2:
                        table_row.append(value.decode('utf8', errors='replace')[len('-----BEGIN PUBLIC KEY-----\n'):])
                    else:
                        table_row.append(value.decode('utf8', errors='replace'))
                public_key_data_decoded.append(table_row)

            components.append(Table((WIDTH - 1125) // 2, 80, ["Timestamp", "Key ID", "Public Key", "Key Size", "User ID"], public_key_data_decoded))
            radio_buttons_temp = G4_radio_buttons[:len(public_key_data)]

            selected_id = -1
            for i in range(len(radio_buttons_temp)):
                if radio_buttons_temp[i].is_selected():
                    selected_id = i

            if(selected_id != -1):
                G2_encription_keyID = public_key_data[selected_id][1].decode('utf8')
                G2_encryption_key = public_key_data[selected_id][2]
                #print(G2_encryption_key)
            else:
                G2_encription_keyID = ""
                G2_encryption_key = b""

            components += radio_buttons_temp
            draw_components(WHITE, components)
            handle_events(components, G4_radio_buttons)

        elif SCREEN_MOD == MOD.TEST:
            components = [return_button]
            components += G4_radio_buttons
            draw_components(WHITE, components)
            handle_events(components, G4_radio_buttons)

        else:
            components = [return_button]
            draw_components(GREEN, components)
            handle_events(components)

        pygame.display.flip()
        clock.tick(30)

m = b'ova poruka je tekstualnog tipa i sluzi kao primer koji se koristi za testiranje rada aes128 algoritma za enkripciju poruke kljuca isto 128 bita'
password = 'casdasdasdasd'
k = hashlib.sha1(password.encode('utf-8')).hexdigest()
k = bytes.fromhex(k)[:16]
print(k)
print(AES128_encryption(m, k))
print(AES128_decryption(AES128_encryption(m, k), k))

key_private = ""


hex_plaintext = "0123456789ABCDEF"

password_des = 'sadailnikada'
password_hash_des = hashlib.sha1(password_des.encode('utf-8')).hexdigest()
password_hash_des = password_hash_des[:32]
print(password_hash_des)

print(f"Plaintext: {hex_plaintext}")
ciphertext = DES_encryption(hex_plaintext, password_hash_des)

print(f"Ciphertext: {ciphertext}")

plaintext = DES_decryption(ciphertext, password_hash_des)
print(f"Plaintext: {plaintext}")

"""
ciphertext_binary = bitarray(hex_to_binary(ch))

print(ciphertext_binary)
plaintext = DES_encryption(ciphertext_binary, key[::-1])
"""

fn = "output.bin"
m = b'Mnogo sam zena pozeleo\r\nSamo sam tebe sanjao\r\nSvakog te dana cekao\r\nVoleo\r\n\r\nPo meri tvojoj, po grudima\r\nMoja je saka stvorena\r\nNa telu tvom\r\nDa zadremam\r\nMoja je ruka navikla\r\nKad bi htela sada\r\nKad bi se setila\r\nDa te na istom mestu\r\nCekam ja'.decode('utf8')
lm = [True, True, False, True]
k1ID = 'XQIDAQAB'
k2ID = 'XQIDAQAB'
an = 0
k1 = b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOMyqEZEhtD1iYopUIa1suCsGx\nnH+MtmCewRlX1hP/B5TOZ6thXDnGJY+pqNhQFwSHekIQaVnDmbXiwGepOmDN3y5Q\ny6JXU7+028lh84j2ABZN3RPmYDgSTEv+47IGJ5GKRMyU/TjOEj5WCl7hSraWA13G\nRNHszpQSTXo1IzmvXQIDAQAB\n-----END PUBLIC KEY-----\n'
k2 = b'-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDOMyqEZEhtD1iYopUIa1suCsGxnH+MtmCewRlX1hP/B5TOZ6th\nXDnGJY+pqNhQFwSHekIQaVnDmbXiwGepOmDN3y5Qy6JXU7+028lh84j2ABZN3RPm\nYDgSTEv+47IGJ5GKRMyU/TjOEj5WCl7hSraWA13GRNHszpQSTXo1IzmvXQIDAQAB\nAoGAU/2leO38Tmgs12eKOza3mkaJZVZw4hk7vA69yviJhp1I8NZrianuYpbUMPB0\nxBLMJn8XP+YZyUHoQ6fJ0bXUzetgptoEXCYJrbSZsLWF0UNvvXe4zTdENngUUE47\nTY8GaKlv+1BKjHNoH0sDx8eJalVvZJXdedWLxKsBDit2rGUCQQD1dPwXj0Xqag18\n6z7vE6QeazKB+zbC4O0ufUr+qzc5vSBE5OYxwo3EGGBwzksGdAa1dwJe5DVD8L3f\nTC3n1TYTAkEA1w6D1LdXAq/ZMlG6uebsPJbfjxb9O+ADZ8t++3/QhwIS+7Bcjz0+\nA4PO4m1uxdN4//VDy4SFBbBNgjwYRxfyzwJAGZ8phWgOO0bwu35u5lPdiNNVxV2s\nvLDv8S9g+a5zqFJGoQpnwP/2/mYxAvV1vWm1HZIbrD4UFVB28W0pSY7nAwJBAIr/\nx7eaVLPY4uKCLtVvaytyPMbojf7AOJNC1S1LHIXWklx5TioK5GUzMWnqX1mf6KpP\nZWVKnwvhOwe9Pdfdo8MCQQCMA/3lS9rpLGRXfh0AMeGKXRRMDoXm64WjH8wwIOZm\nnKH9diGxxd9n9e7M4YZMWiDb1TOw2D/5YaQUsSIzg3VV\n-----END RSA PRIVATE KEY-----\n'

encrypt_message(fn, m, lm, k1ID, k2ID, an, k1, k2)

#main()