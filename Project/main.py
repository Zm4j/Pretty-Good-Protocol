import sys
from components import *
from algorithms import *

pygame.init()

# PODSETNIK, NAPRAVI VISE EKRANA pygame.display.set_mode((WIDTH, HEIGHT)), I NAPRAVI DA SE MENJAJU
main_screen = pygame.display.set_mode((WIDTH, HEIGHT)

pygame.display.set_caption("PGP")


def set_screen_mod(x):
    global SCREEN_MOD
    SCREEN_MOD = x


def main():
    clock = pygame.time.Clock()

    key = TextBox(50, 50, 200, 50)
    password = TextBox(50, 150, 200, 50)

    generate_key = Button((WIDTH-BUTTON_WIDTH)//2, (HEIGHT-8*BUTTON_HEIGHT)//3, BUTTON_WIDTH, BUTTON_HEIGHT, "Generate Key", lambda: set_screen_mod(MOD.GENERATE))
    encrypt_message = Button((WIDTH-BUTTON_WIDTH)//2, (HEIGHT)//3, BUTTON_WIDTH, BUTTON_HEIGHT, "Encrypt Message", lambda: set_screen_mod(MOD.ENCRYPT))
    decrypt_message = Button((WIDTH-BUTTON_WIDTH)//2, (HEIGHT+8*BUTTON_HEIGHT)//3, BUTTON_WIDTH, BUTTON_HEIGHT, "Decrypt Message", lambda: set_screen_mod(MOD.DECRYPT))
    test_button = Button((WIDTH - BUTTON_WIDTH) // 2, (HEIGHT + 12 * BUTTON_HEIGHT) // 3, BUTTON_WIDTH, BUTTON_HEIGHT, "TEST", lambda: set_screen_mod(MOD.TEST))
    main_page = Button(0, 0, BUTTON_WIDTH/2, BUTTON_HEIGHT/2, "return", lambda: set_screen_mod(MOD.DEFAULT))

    column_names = ["Name", "Age", "Gender"]
    data = [
        ["Alice", 25, "Female"],
        ["Bob", 30, "Male"],
        ["Charlie", 40, "Male"],
        ["Diana", 35, "Female"],
        ["Eve", 20, "Female"]
    ]

    table = Table(50, 450, column_names, data)

    checkboxes = []
    checkbox_y = 50
    for i in range(5):
        checkboxes.append(CheckBox(350, checkbox_y, 20, f"Checkbox {i + 1}"))
        checkbox_y += 70

    textboxes = [key, password]
    buttons = [generate_key, encrypt_message, decrypt_message, test_button, main_page]

    while True:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                pygame.quit()
                sys.exit()
            for textbox in textboxes:
                textbox.handle_event(event)
            for button in buttons:
                button.handle_event(event)
            for checkbox in checkboxes:
                checkbox.handle_event(event)

        main_screen.fill(WHITE)
        if SCREEN_MOD == MOD.TEST:
            main_screen.fill(WHITE)
            for textbox in textboxes:
                textbox.draw(main_screen)
            # for button in buttons:
            #     button.draw(main_screen)
            for checkbox in checkboxes:
                checkbox.draw(main_screen)
            table.draw(main_screen)
        elif SCREEN_MOD == MOD.DEFAULT:
            for button in buttons:
                button.draw(main_screen)
        elif SCREEN_MOD == MOD.GENERATE:
            main_screen.fill(YELLOW)
        elif SCREEN_MOD == MOD.ENCRYPT:
            main_screen.fill(LIGHT_BLUE)
        elif SCREEN_MOD == MOD.DECRYPT:
            main_screen.fill(PURPLE)
        else:
            main_screen.fill(GREEN)

        main_page.draw(main_screen)

        pygame.display.flip()
        clock.tick(30)


main()
