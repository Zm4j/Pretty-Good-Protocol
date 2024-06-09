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
    G2_massage = TextBox((WIDTH - BUTTON_WIDTH) // 2, 50, 350, 50)
    G1_email = TextBox((WIDTH - BUTTON_WIDTH) // 2, 150, 350, 50)
    G1_bits = TextBox((WIDTH - BUTTON_WIDTH) // 2, 250, 350, 50)
    G1_password = TextBox((WIDTH - BUTTON_WIDTH) // 2, 350, 350, 50)

    checkboxes = []
    checkbox_y = 50
    for i in range(5):
        checkboxes.append(CheckBox(350, checkbox_y, 20, f"Checkbox {i + 1}"))
        checkbox_y += 70

    radio_buttons = [
        RadioButton(100, 100, "Option 1"),
        RadioButton(100, 150, "Option 2"),
        RadioButton(100, 200, "Option 3")
    ]

    ind = 0
    while True:
        clearscreen()

        if SCREEN_MOD == MOD.DEFAULT:
            components = []
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"Generate Key", lambda: set_screen_mod(MOD.GENERATE)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "View Key Tables",lambda: set_screen_mod(MOD.KEY_TABLE_VIEW)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"Encrypt Message", lambda: set_screen_mod(MOD.ENCRYPT)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 12 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"Decrypt Message", lambda: set_screen_mod(MOD.DECRYPT)))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 18 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,"TEST", lambda: set_screen_mod(MOD.TEST)))
            draw_components(WHITE, components)
            handle_events(components)

            if G1_name.getText() != '' and G1_email.getText() != '' and G1_bits.getText() != '' and G1_password.getText() != '' and ind == 0:
                GENERATE_KEY_VALUES.append(G1_name.getText())
                GENERATE_KEY_VALUES.append(G1_email.getText())
                GENERATE_KEY_VALUES.append(G1_bits.getText())
                GENERATE_KEY_VALUES.append(G1_password.getText())
                generate_keys(GENERATE_KEY_VALUES)
                ind = 1

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
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Encrypt",
                                     lambda: encrypt_message('output.bin')))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Autentification",
                                     lambda: authentication()
                                     ))
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Radix-64",
                                     lambda: radix_64()
                                     ))
            draw_components(LIGHT_BLUE, components)
            handle_events(components)

        elif SCREEN_MOD == MOD.DECRYPT:
            components = [return_button]
            components.append(Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Decript",lambda: decrypt_message('output.bin')))
            draw_components(PURPLE, components)
            handle_events(components)

        elif SCREEN_MOD == MOD.TEST:
            components = [return_button]
            components += checkboxes + radio_buttons
            draw_components(WHITE, components)
            handle_events(components, radio_buttons)

        elif SCREEN_MOD == MOD.KEY_TABLE_VIEW:
            private_key_data = get_keys_from_files("./Keys", filter_private=True)
            public_key_data = get_keys_from_files("./Keys")

            components = [return_button]
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

main()