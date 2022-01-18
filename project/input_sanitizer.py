# nazwa użytkownika może składać się wyłącznie z małych liter a-z, powinna być napisem o długości od 1 do 100 znaków
import re


def is_lowercase_only(s):
    return re.match("^[a-z]+$", s)


def validate_name(name):
    if 0 < len(name) <= 100:
        if is_lowercase_only(name):
            return name
    return None
