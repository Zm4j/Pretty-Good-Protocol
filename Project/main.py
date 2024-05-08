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

    key = TextBox(50, 50, 250, 50)
    password_0 = TextBox(50, 150, 250, 50)

    name = TextBox((WIDTH - BUTTON_WIDTH) // 2, 50, 350, 50)
    email = TextBox((WIDTH - BUTTON_WIDTH) // 2, 150, 350, 50)
    bits = TextBox((WIDTH - BUTTON_WIDTH) // 2, 250, 350, 50)
    password = TextBox((WIDTH - BUTTON_WIDTH) // 2, 350, 350, 50)

    generate_key = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT - 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,
                          "Generate Key", lambda: set_screen_mod(MOD.GENERATE))
    encrypt_message = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "Encrypt Message",
                             lambda: set_screen_mod(MOD.ENCRYPT))
    decrypt_message = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 6 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH,
                             BUTTON_HEIGHT, "Decrypt Message", lambda: set_screen_mod(MOD.DECRYPT))
    test_button = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 12 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT,
                         "TEST", lambda: set_screen_mod(MOD.TEST))
    main_page = Button(0, 0, BUTTON_WIDTH / 2, BUTTON_HEIGHT / 2, "return", lambda: set_screen_mod(MOD.DEFAULT))

    column_names = ["Name", "Age", "Gender"]
    data = [
        ["Alice", 25, "Female"],
        ["Bob", 30, "Male"],
        ["Charlie", 40, "Male"],
        ["Diana", 35, "Female"],
        ["Eve", 20, "Female"]
    ]

    tables = []
    table = Table(50, 450, column_names, data)
    tables.append(table)

    checkboxes = []
    checkbox_y = 50
    for i in range(5):
        checkboxes.append(CheckBox(350, checkbox_y, 20, f"Checkbox {i + 1}"))
        checkbox_y += 70

    textboxes = [key, password_0]
    buttons = [generate_key, encrypt_message, decrypt_message, test_button, main_page]

    while True:
        clearscreen()

        if SCREEN_MOD == MOD.TEST:
            buttons_test = [main_page]
            draw_components(WHITE, buttons_test, textboxes, checkboxes, tables, [])
            handle_events(buttons_test, textboxes, checkboxes)

        elif SCREEN_MOD == MOD.DEFAULT:
            draw_components(WHITE, buttons, [], [], [], [])
            handle_events(buttons, [], [])

        elif SCREEN_MOD == MOD.GENERATE:
            # TODO MOD treba da se menja !!!
            add_button = Button((WIDTH - BUTTON_WIDTH) // 2, 430, BUTTON_WIDTH, BUTTON_HEIGHT, "add",
                                lambda: set_screen_mod(MOD.DEFAULT))
            buttons_generate = [main_page, add_button]
            name_label = Label("Name: ", 100, 60)
            email_label = Label("e-mail: ", 100, 160)
            bits_label = Label("Bits: ", 100, 260)
            password_label = Label("Password: ", 100, 360)

            labels = [name_label, email_label, bits_label, password_label]
            textboxes_generate = [name, email, bits, password]
            draw_components(YELLOW, buttons_generate, textboxes_generate, [], [], labels)
            handle_events(buttons_generate, textboxes_generate, [])

        elif SCREEN_MOD == MOD.ENCRYPT:
            buttons_encrypt = [main_page]
            draw_components(LIGHT_BLUE, buttons_encrypt, [], [], [], [])
            handle_events(buttons_encrypt, [], [])

        elif SCREEN_MOD == MOD.DECRYPT:
            buttons_decrypt = [main_page]
            draw_components(PURPLE, buttons_decrypt, [], [], [], [])
            handle_events(buttons_decrypt, [], [])

        else:
            buttons_else = [main_page]
            draw_components(GREEN, buttons_else, [], [], [], [])
            handle_events(buttons_else, [], [])

        pygame.display.flip()
        # pygame.display.update()
        clock.tick(30)


main()
