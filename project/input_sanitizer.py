# nazwa użytkownika może składać się wyłącznie z małych liter a-z, powinna być napisem o długości od 1 do 100 znaków
import re

import flask


class NameStatus:
    INVALID_NAME = 0
    PROPER_NAME = 1


class PasswordStatus:
    PROPER_PASSWORD = 0
    INVALID_PASSWORD = 1
    ILLEGAL_CHARS = 2


def is_lowercase_only(s):
    return re.match("^[a-z]+$", s)


def validate_name(name):
    if 0 < len(name) <= 100:
        if is_lowercase_only(name):
            return NameStatus.PROPER_NAME
    return NameStatus.INVALID_NAME


def validate_password(password):
    if re.match("\'|\"|&|-", password):
        return PasswordStatus.ILLEGAL_CHARS
    if 5 < len(password) < 100 and any(map(str.isdigit, password)) and any(map(str.islower, password)) and any(map(str.isupper, password)):
        return PasswordStatus.PROPER_PASSWORD
    return PasswordStatus.INVALID_PASSWORD


def sanitize_text(input_text):
    return flask.Markup.escape(input_text)


def display_text(markup_text):
    return flask.Markup.unescape(markup_text)
