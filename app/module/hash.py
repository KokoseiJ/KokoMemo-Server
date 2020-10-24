# -*- coding: utf-8 -*-

import hmac
import hashlib

from app.module import b64


def sha256(password: [bytes, str]):
    """
    Simple wrapper function for hashing password using SHA256 algorithm.

    :param password: Password to be hashed. It has to be either bytes or str.
                     If it has a type of str, This will be encoded to bytes.
    :returns: base64 encoded SHA256 hashed password in bytes.
    """
    if isinstance(password, str):
        password = password.encode()

    return b64.b64encode(
        data=hashlib.sha256(password).digest(),
        urlsafe=False
    )


def hmacsha256(data: [bytes, str], key):
    """
    Simple wrapper function for generating HMAC SHA256 signature.
    :param data: data to be hashed. It has to be either bytes or str.
                 If it has a type of str, This will be encoded to bytes.
    :param key: #TODO: ADD Docstring
    :returns: HMAC SHA256 signed data in bytes.
    """
    if isinstance(data, str):
        data = data.encode()

    return hmac.digest(
        key=key,
        msg=data,
        digest="sha256"
    )
