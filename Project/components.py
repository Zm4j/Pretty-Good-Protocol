import pygame
from enum import Enum


class MOD(Enum):
    TEST = -1
    DEFAULT = 0
    GENERATE = 1
    ENCRYPT = 2
    DECRYPT = 3


WIDTH, HEIGHT = 800, 600
BUTTON_WIDTH, BUTTON_HEIGHT = 200, 50
TEXTBOX_WIDTH, TEXTBOX_HEIGHT = 500, 50

WHITE = (255, 255, 255)
GRAY = (200, 200, 200)
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
        self.rect = pygame.Rect(x, y, w, h)
        self.text = ""
        self.active = False

    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.rect.collidepoint(event.pos):
                self.active = not self.active
            else:
                self.active = False
        if event.type == pygame.KEYDOWN and self.active:
            if event.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            else:
                self.text += event.unicode

    def draw(self, screen):
        font = pygame.font.Font(None, 25)
        outline_color = BLACK if self.active else GRAY
        pygame.draw.rect(screen, outline_color, self.rect, 2)
        pygame.draw.rect(screen, WHITE, self.rect.inflate(-4, -4))
        if self.text != "":
            text_surface = font.render(self.text, True, BLACK)
            screen.blit(text_surface, (self.rect.x + 5, self.rect.y + 5))


class Button:
    def __init__(self, x, y, w, h, text, callback):
        self.rect = pygame.Rect(x, y, w, h)
        self.text = text
        self.callback = callback

    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.rect.collidepoint(event.pos):
                self.callback()

    def getName(self):
        return self.text

    def draw(self, screen):
        font = pygame.font.Font(None, 25)
        pygame.draw.rect(screen, GRAY, self.rect)
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

    def draw(self, screen):
        font = pygame.font.Font(None, 25)
        pygame.draw.rect(screen, BLACK, self.rect, 2)
        if self.checked:
            pygame.draw.rect(screen, BLACK, self.rect.inflate(-8, -8))
        text_surface = font.render(self.text, True, BLACK)
        screen.blit(text_surface, (self.rect.x + 30, self.rect.y))


class Table:
    def __init__(self, x, y, column_names, data):
        self.x = x
        self.y = y
        self.column_names = column_names
        self.data = data
        self.num_columns = len(column_names)
        self.num_rows = len(data)
        self.column_width = 150
        self.row_height = 20
        self.header_height = 25
        self.cell_padding = 5

    def draw(self, screen):
        font = pygame.font.Font(None, 25)
        # Draw column headers
        for i, column_name in enumerate(self.column_names):
            header_rect = pygame.Rect(self.x + i * self.column_width, self.y, self.column_width, self.header_height)
            pygame.draw.rect(screen, GRAY, header_rect)
            text_surface = font.render(column_name, True, BLACK)
            text_rect = text_surface.get_rect(center=header_rect.center)
            screen.blit(text_surface, text_rect)

        # Draw data cells
        for row_index, row_data in enumerate(self.data):
            for col_index, cell_data in enumerate(row_data):
                cell_rect = pygame.Rect(self.x + col_index * self.column_width,
                                        self.y + self.header_height + row_index * self.row_height,
                                        self.column_width, self.row_height)
                pygame.draw.rect(screen, WHITE, cell_rect)
                text_surface = font.render(str(cell_data), True, BLACK)
                text_rect = text_surface.get_rect(center=cell_rect.center)
                screen.blit(text_surface, text_rect)


class Label:
    def __init__(self, text, x, y, font_size=32, font_color=BLACK):
        self.text = text
        self.x = x
        self.y = y
        self.font = pygame.font.Font(None, font_size)
        self.font_color = font_color

    def draw(self, screen):
        text_surface = self.font.render(self.text, True, self.font_color)
        screen.blit(text_surface, (self.x, self.y))
