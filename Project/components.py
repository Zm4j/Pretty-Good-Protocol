from enum import Enum
import pyperclip
import pygame


class MOD(Enum):
    TEST = -1
    DEFAULT = 0
    GENERATE = 1
    ENCRYPT = 2
    DECRYPT = 3
    KEY_TABLE_VIEW = 4
    SELECT_KEY_E = 5
    SELECT_KEY_V = 6


WIDTH, HEIGHT = 1500, 800
BUTTON_WIDTH, BUTTON_HEIGHT = 200, 50
TEXTBOX_WIDTH, TEXTBOX_HEIGHT = 500, 50

WHITE = (255, 255, 255)
DARK_GRAY = (100, 100, 100)
GRAY = (180, 180, 180)
LIGHT_GRAY = (220, 220, 220)
BLACK = (0, 0, 0)
RED = (255, 0, 0)
YELLOW = (255, 255, 0)
GREEN = (0, 255, 0)
LIGHT_BLUE = (0, 255, 255)
BLUE = (0, 0, 255)
PURPLE = (255, 0, 255)

SCREEN_MOD = MOD.DEFAULT


class TextBox:
    def __init__(self, x, y, w, h):
        self.width = w
        self.height = h
        self.rect = pygame.Rect(x, y, w, h)
        self.text = ""
        self.active = False
        self.font = pygame.font.SysFont('Consolas', 18)
        self.h_text_position = 0
        self.width_text = self.width * 179 // 1800
        self.num_lines = (self.height-2 + 19) // 20

    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.rect.collidepoint(event.pos):
                self.active = not self.active
            else:
                self.active = False

        if event.type == pygame.KEYDOWN and self.active:
            if event.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            elif event.key == pygame.K_v and (
                    pygame.key.get_mods() & pygame.KMOD_CTRL or pygame.key.get_mods() & pygame.KMOD_META):
                clipboard_text = pyperclip.paste()
                if clipboard_text:
                    self.text += clipboard_text
            elif event.key == pygame.K_DELETE and (
                    pygame.key.get_mods() & pygame.KMOD_CTRL or pygame.key.get_mods() & pygame.KMOD_META):
                self.text = ""
            elif event.key == pygame.K_DOWN:
                self.h_text_position = max(0, self.h_text_position-1)
            elif event.key == pygame.K_UP:
                if (len(self.text)+self.width_text-1)//self.width_text - self.num_lines - self.h_text_position <= 0:
                    pass
                else:
                    self.h_text_position += 1
            else:
                self.text += event.unicode

    def update(self, mouse_pos):
        pass

    def draw(self, screen):
        font = self.font
        outline_color = BLACK if self.active else GRAY
        pygame.draw.rect(screen, outline_color, self.rect, 2)
        pygame.draw.rect(screen, WHITE, self.rect.inflate(-4, -4))
        i = max(0, (len(self.text)+self.width_text-1)//self.width_text - self.num_lines - self.h_text_position) * self.width_text
        i_end = i + self.num_lines * self.width_text
        j = 0
        while i < i_end:
            text_surface = font.render(self.text[i:i+self.width_text], True, BLACK)
            screen.blit(text_surface, (self.rect.x + 5, self.rect.y + 5 + 17*(j//self.width_text)))
            j += self.width_text
            i += self.width_text

    def getText(self):
        return self.text

    def setText(self, text):
        self.text = text


class Button:
    def __init__(self, x, y, w, h, text, callback):
        self.rect = pygame.Rect(x, y, w, h)
        self.text = text
        self.callback = callback
        self.default_color = GRAY
        self.hover_color = LIGHT_GRAY
        self.color = self.default_color

    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.rect.collidepoint(event.pos):
                self.callback()

    def update(self, mouse_pos):
        if self.rect.collidepoint(mouse_pos):
            self.color = self.hover_color
        else:
            self.color = self.default_color

    def getName(self):
        return self.text

    def draw(self, screen):
        font = pygame.font.Font(None, 25)
        pygame.draw.rect(screen, self.color, self.rect)
        text_surface = font.render(self.text, True, BLACK)
        text_rect = text_surface.get_rect(center=self.rect.center)
        screen.blit(text_surface, text_rect)


class CheckBox:
    def __init__(self, x, y, size, text):
        self.rect = pygame.Rect(x, y, size, size)
        self.checked = False
        self.text = text

    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.rect.collidepoint(event.pos):
                self.checked = not self.checked

    def update(self, mouse_pos):
        pass

    def draw(self, screen):
        font = pygame.font.Font(None, 25)
        pygame.draw.rect(screen, BLACK, self.rect, 2)
        if self.checked:
            pygame.draw.rect(screen, BLACK, self.rect.inflate(-8, -8))
        text_surface = font.render(self.text, True, BLACK)
        screen.blit(text_surface, (self.rect.x + 30, self.rect.y))

    def isChecked(self):
        return self.checked

    def set_value(self, value):
        self.checked = value


class Table:
    def __init__(self, x, y, column_names, data, column_width=None):
        if column_width is None:
            column_width = [225, 225, 225, 225, 225, 225]
        self.x = x
        self.y = y
        self.column_names = column_names
        self.data = data
        self.num_columns = len(column_names)
        self.num_rows = len(data)
        self.column_width = column_width
        self.row_height = 20
        self.header_height = 25
        self.cell_padding = 5

    def handle_event(self, event):
        pass

    def update(self, mouse_pos):
        pass

    def draw(self, screen):
        font = pygame.font.Font(None, 25)
        # Draw column headers
        agg_col_width = 0
        for i, column_name in enumerate(self.column_names):
            header_rect = pygame.Rect(self.x + agg_col_width, self.y, self.column_width[i], self.header_height)
            pygame.draw.rect(screen, GRAY, header_rect)
            text_surface = font.render(column_name, True, BLACK)
            text_rect = text_surface.get_rect(center=header_rect.center)
            screen.blit(text_surface, text_rect)
            agg_col_width += self.column_width[i]

        # Draw data cells
        for row_index, row_data in enumerate(self.data):
            agg_col_width = 0
            for col_index, cell_data in enumerate(row_data):
                if col_index >= len(self.column_names):
                    continue
                cell_rect = pygame.Rect(self.x + agg_col_width,
                                        self.y + self.header_height + row_index * self.row_height,
                                        self.column_width[col_index], self.row_height)
                pygame.draw.rect(screen, LIGHT_GRAY, cell_rect)
                text_surface = font.render(str(cell_data if len(cell_data) < 22 else cell_data[:19]+"..."), True, BLACK)
                text_rect = text_surface.get_rect(center=cell_rect.center)
                screen.blit(text_surface, text_rect)
                agg_col_width += self.column_width[col_index]


class Label:
    def __init__(self, text, x, y, font_size=32, font_color=BLACK):
        self.text = text
        self.x = x
        self.y = y
        self.font = pygame.font.Font(None, font_size)
        self.font_color = font_color

    def update(self, mouse_pos):
        pass

    def handle_event(self, event):
        pass

    def draw(self, screen):
        text_surface = self.font.render(self.text, True, self.font_color)
        screen.blit(text_surface, (self.x, self.y))


class RadioButton:
    def __init__(self, x, y, text, radius=10, color=GRAY, selected_color=BLACK, font_size=32, font_color=BLACK):
        self.x = x
        self.y = y
        self.radius = radius
        self.color = color
        self.selected_color = selected_color
        self.text = text
        self.font = pygame.font.Font(None, font_size)
        self.font_color = font_color
        self.selected = False

    def draw(self, screen):
        # Draw the outer circle
        pygame.draw.circle(screen, self.color, (self.x, self.y), self.radius)

        # Draw the inner circle if selected
        if self.selected:
            pygame.draw.circle(screen, self.selected_color, (self.x, self.y), self.radius)

        # Draw the text
        text_surface = self.font.render(self.text, True, self.font_color)
        screen.blit(text_surface, (self.x + self.radius + 10, self.y - text_surface.get_height() // 2))

    def update(self, mouse_pos):
        pass

    def is_clicked(self, mouse_pos):
        # Check if the radio button is clicked
        distance = ((mouse_pos[0] - self.x) ** 2 + (mouse_pos[1] - self.y) ** 2) ** 0.5
        return distance <= self.radius

    def handle_event(self, event, group):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            if self.is_clicked(event.pos):
                for button in group:
                    button.selected = False
                self.selected = True

    def is_selected(self):
        return self.selected

    def clear(self):
        self.selected = False