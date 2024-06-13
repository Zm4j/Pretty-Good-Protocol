import sys

import gmpy2 as gmpy2
import pygame as pygame
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
    G1_bits = TextBox((WIDTH - BUTTON_WIDTH) // 2, 250, 350, 50)
    G1_password = TextBox((WIDTH - BUTTON_WIDTH) // 2, 350, 350, 50)

    G2_massage = TextBox((WIDTH - BUTTON_WIDTH) // 2, 50, 350, 50)
    G2_file_name = TextBox((WIDTH - BUTTON_WIDTH) // 2, 150, 350, 50)
    G2_checkboxes = [CheckBox(200, 300 + i*80, 20, ["TAJNOST", "AUTENTIKACIJA", "KOMPRESIJA", "RADIX64"][i]) for i in range(4)]
    G2_encription_key = ""
    G2_verify_key = ""

    G4_user_id = TextBox(50, HEIGHT-100, 350, 50)

    radio_buttons = [
        RadioButton(100, 100, "Option 1"),
        RadioButton(100, 150, "Option 2"),
        RadioButton(100, 200, "Option 3")
    ]

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

            if G1_name.getText() != '' and G1_email.getText() != '' and G1_bits.getText() != '' and G1_password.getText() != '':
                GENERATE_KEY_VALUES.append(G1_name.getText())
                GENERATE_KEY_VALUES.append(G1_email.getText())
                GENERATE_KEY_VALUES.append(G1_bits.getText())
                GENERATE_KEY_VALUES.append(G1_password.getText())
                generate_keys(GENERATE_KEY_VALUES)

            G1_name.setText("")
            G1_password.setText("")
            G1_bits.setText("")
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
            components.append(G1_bits)
            components.append(G1_password)

            draw_components(YELLOW, components)
            handle_events(components)

        elif SCREEN_MOD == MOD.ENCRYPT:
            components = [return_button]
            components.append(Label("Message : ", 100, 60))
            components.append(G2_massage)
            components.append(Label("File name : ", 100, 160))
            components.append(G2_file_name)

            list_modes = [G2_checkboxes[i].isChecked() for i in range(4)]

            if G2_checkboxes[0].isChecked():
                components.append(Button((WIDTH - BUTTON_WIDTH) // 2 + 200, (HEIGHT - 6 * BUTTON_HEIGHT)*7 // 6, BUTTON_WIDTH, BUTTON_HEIGHT, "ENCRIPTION KEY",lambda: set_screen_mod(MOD.SELECT_KEY)))

            if G2_checkboxes[1].isChecked():
                components.append(Button((WIDTH - BUTTON_WIDTH) // 2 - 200, (HEIGHT - 6 * BUTTON_HEIGHT)*7 // 6, BUTTON_WIDTH, BUTTON_HEIGHT, "VERIFY KEY",lambda: set_screen_mod(MOD.SELECT_KEY)))

            if not(G2_checkboxes[0].isChecked() and G2_encription_key == "") and not(G2_checkboxes[1].isChecked() and G2_verify_key==""):
                components.append(Button((WIDTH - BUTTON_WIDTH) // 2, HEIGHT - 150, BUTTON_WIDTH, BUTTON_HEIGHT, "Encrypt",lambda: encrypt_message('output.bin', G2_massage.getText(), list_modes)))

            draw_components(LIGHT_BLUE, components + G2_checkboxes)
            handle_events(components + G2_checkboxes)
            # components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Autentification",lambda: authentication()))
            # components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Radix-64",lambda: radix_64()))

        elif SCREEN_MOD == MOD.DECRYPT:
            components = [return_button]
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Decript",lambda: decrypt_message('output.bin')))
            draw_components(PURPLE, components)
            handle_events(components)

        elif SCREEN_MOD == MOD.TEST:
            components = [return_button]
            components += radio_buttons
            draw_components(WHITE, components)
            handle_events(components, radio_buttons)

        elif SCREEN_MOD == MOD.KEY_TABLE_VIEW:
            filter_id = G4_user_id.getText()
            if filter_id == "see_all_keys":
                filter_id = None
            private_key_data = get_keys_from_files("./Keys", filter_private=True, filter_user=filter_id)
            public_key_data = get_keys_from_files("./Keys",  filter_user=filter_id)

            components = [return_button, G4_user_id]
            components.append(Label("RSA PRIVATE KEY TABLE", (WIDTH - 300) // 2, 40))
            components.append(Label("RSA PUBLIC KEY TABLE", (WIDTH - 300) // 2, HEIGHT // 2))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 2 * BUTTON_HEIGHT), BUTTON_WIDTH, BUTTON_HEIGHT,"SAVE TABLE", lambda: set_screen_mod(MOD.KEY_TABLE_VIEW)))
            components.append(Table((WIDTH - 1350) // 2, 80,["Timestamp", "Key ID", "Public Key", "Encrypted Private Key", "Key Size", "User ID"],private_key_data))
            components.append(Table((WIDTH - 1125) // 2, HEIGHT // 2 + 40, ["Timestamp", "Key ID", "Public Key", "Key Size", "User ID"],public_key_data))

            draw_components(WHITE, components)
            handle_events(components)

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

#main()