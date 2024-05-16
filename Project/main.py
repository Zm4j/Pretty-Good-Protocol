import random
import sys
from components import *
from algorithms import *

pygame.init()

# PODSETNIK, NAPRAVI VISE EKRANA pygame.display.set_mode((WIDTH, HEIGHT)), I NAPRAVI DA SE MENJAJU
main_screen = pygame.display.set_mode((WIDTH, HEIGHT))

pygame.display.set_caption("PGP")


def set_screen_mod(x):
    global SCREEN_MOD
    SCREEN_MOD = x


def clearscreen():
    main_screen.fill(WHITE)


def handle_events(buttons, textboxes, checkboxes):
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            pygame.quit()
            sys.exit()
        for textbox in textboxes:
            textbox.handle_event(event)
        for checkbox in checkboxes:
            checkbox.handle_event(event)
        for button in buttons:
            button.handle_event(event)


def draw_components(color, buttons, textboxes, checkboxes, tables, labels):
    main_screen.fill(color)
    for textbox in textboxes:
        textbox.draw(main_screen)
    for checkbox in checkboxes:
        checkbox.draw(main_screen)
    for table in tables:
        table.draw(main_screen)
    for button in buttons:
        button.draw(main_screen)
    for label in labels:
        label.draw(main_screen)


def main():
    clock = pygame.time.Clock()

    data = [
        ["12:34:56", hex(random.randint(0, 2 ** 64)), str(hex(random.randint(0, 2**90)))+"...", str(hex(random.randint(0, 2**90)))+"...",
         "jj200083d@student.etf.bg.ac.rs"],
        ["06:09:06", hex(random.randint(0, 2 ** 64)), str(hex(random.randint(0, 2**90)))+"...", str(hex(random.randint(0, 2**90)))+"...",
         "jj200083d@student.etf.bg.ac.rs"],
        ["00:00:00", hex(random.randint(0, 2 ** 64)), str(hex(random.randint(0, 2**90)))+"...", str(hex(random.randint(0, 2**90)))+"...",
         "jj200083d@student.etf.bg.ac.rs"],
        ["05:19:23", hex(random.randint(0, 2 ** 64)), str(hex(random.randint(0, 2**90)))+"...", str(hex(random.randint(0, 2**90)))+"...",
         "jj200083d@student.etf.bg.ac.rs"],
        ["17:17:18", hex(random.randint(0, 2 ** 64)), str(hex(random.randint(0, 2**90)))+"...", str(hex(random.randint(0, 2**90)))+"...",
         "jj200083d@student.etf.bg.ac.rs"],
    ]

    generate_key = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Generate Key", lambda: set_screen_mod(MOD.GENERATE))
    key_table_view_button = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "View Key Tables", lambda: set_screen_mod(MOD.KEY_TABLE_VIEW))
    encrypt_message = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Encrypt Message", lambda: set_screen_mod(MOD.ENCRYPT))
    decrypt_message = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 12 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Decrypt Message", lambda: set_screen_mod(MOD.DECRYPT))
    test_button = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 18 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "TEST", lambda: set_screen_mod(MOD.TEST))

    return_button = Button(0, 0, BUTTON_WIDTH // 2, BUTTON_HEIGHT // 2, "return", lambda: set_screen_mod(MOD.DEFAULT))

    # components for generate mod
    G1_name = TextBox((WIDTH - BUTTON_WIDTH) // 2, 50, 350, 50)
    G1_email = TextBox((WIDTH - BUTTON_WIDTH) // 2, 150, 350, 50)
    G1_bits = TextBox((WIDTH - BUTTON_WIDTH) // 2, 250, 350, 50)
    G1_password = TextBox((WIDTH - BUTTON_WIDTH) // 2, 350, 350, 50)

    checkboxes = []
    checkbox_y = 50
    for i in range(5):
        checkboxes.append(CheckBox(350, checkbox_y, 20, f"Checkbox {i + 1}"))
        checkbox_y += 70

    while True:
        clearscreen()

        if SCREEN_MOD == MOD.DEFAULT:
            buttons = [generate_key, encrypt_message, decrypt_message, test_button, key_table_view_button]
            draw_components(WHITE, buttons, [], [], [], [])
            handle_events(buttons, [], [])

        elif SCREEN_MOD == MOD.GENERATE:
            # TODO MOD treba da se menja !!!
            add_button = Button((WIDTH - BUTTON_WIDTH) // 2, 430, BUTTON_WIDTH, BUTTON_HEIGHT, "add", lambda: set_screen_mod(MOD.DEFAULT))
            buttons_generate = [return_button, add_button]
            name_label = Label("Name: ", 100, 60)
            email_label = Label("e-mail: ", 100, 160)
            bits_label = Label("Bits: ", 100, 260)
            password_label = Label("Password: ", 100, 360)

            labels = [name_label, email_label, bits_label, password_label]
            textboxes_generate = [G1_name, G1_email, G1_bits, G1_password]
            draw_components(YELLOW, buttons_generate, textboxes_generate, [], [], labels)
            handle_events(buttons_generate, textboxes_generate, [])

        elif SCREEN_MOD == MOD.ENCRYPT:
            buttons_encrypt = [return_button]
            draw_components(LIGHT_BLUE, buttons_encrypt, [], [], [], [])
            handle_events(buttons_encrypt, [], [])

        elif SCREEN_MOD == MOD.DECRYPT:
            buttons_decrypt = [return_button]
            draw_components(PURPLE, buttons_decrypt, [], [], [], [])
            handle_events(buttons_decrypt, [], [])

        elif SCREEN_MOD == MOD.TEST:
            buttons_test = [return_button]
            draw_components(WHITE, buttons_test, [], checkboxes, [], [])
            handle_events(buttons_test, [], checkboxes)

        elif SCREEN_MOD == MOD.KEY_TABLE_VIEW:
            KTV1_table_name = Label("RSA PRIVATE KEY TABLE", (WIDTH - 300) // 2, 40)
            KTV1_table_name2 = Label("RSA PUBLIC KEY TABLE", (WIDTH - 300) // 2, HEIGHT//2 + 40)
            KTV1_save_table_button = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 2 * BUTTON_HEIGHT), BUTTON_WIDTH, BUTTON_HEIGHT, "SAVE TABLE", lambda: set_screen_mod(MOD.KEY_TABLE_VIEW))
            buttons_ktv = [return_button, KTV1_save_table_button]

            private_key_table = Table((WIDTH-1250)//2, 80, ["Timestamp", "Key ID", "Public Key", "Encrypted Private Key", "User ID"], data)
            data1 = [[row[0], row[1], row[2], row[4]] for row in data]
            public_key_table = Table((WIDTH - 940) // 2, HEIGHT//2 + 80, ["Timestamp", "Key ID", "Public Key", "User ID"], data1)

            draw_components(WHITE, buttons_ktv, [], [], [private_key_table, public_key_table], [KTV1_table_name, KTV1_table_name2])
            handle_events(buttons_ktv, [], [])

        else:
            buttons_else = [return_button]
            draw_components(GREEN, buttons_else, [], [], [], [])
            handle_events(buttons_else, [], [])

        pygame.display.flip()
        # pygame.display.update()
        clock.tick(30)


main()
