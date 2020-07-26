color_none   = '\x1b[0m'
color_grey   = '\x1b[1;90m'
color_red    = '\x1b[1;91m'
color_green  = '\x1b[1;92m'
color_purple = '\x1b[1;95m'
color_cyan   = '\x1b[1;96m'

cs_box_head = '┬                   ┬'
cs_box_tail = '┴                   ┴'

ap_box_head = '┬                   ┬            ┬         ┬'
ap_box_tail = '┴                   ┴            ┴         ┴'

# Runtime messages
def print_message(s: str, icon = '+', icon_color = color_green):
    print(f'{color_grey}[{icon_color}{icon}{color_grey}]{color_none} {s}')

# Runtime warnings
def print_warning(s: str, icon = '-', icon_color = color_red):
    print(f'{color_grey}[{icon_color}{icon}{color_grey}]{color_none} {s}')

# Exceptions
def print_exception(x: Exception, icon = '!', icon_color = color_red):
    s = str(x)
    t = type(x).__name__

    print(f'{color_grey}[{icon_color}{icon}{color_grey}]{color_none} {t}: {s}')
