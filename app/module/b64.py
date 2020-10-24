# -*- coding: utf-8 -*-

import base64


def b64encode(data, urlsafe=True):
    """
    Simple wrapper function for encoding base64 string.

    :param data: Data to be encoded. It has to be either bytes or str.
                 If it has a type of str, This will be encoded to bytes.
    :param urlsafe: Determines if it has to be urlsafe or not. Default value
                    is True.
    :returns: base64 encoded data.
    """
    if isinstance(data, str):
        data = data.encode()

    if urlsafe:
        return base64.urlsafe_b64encode(data)
    else:
        return base64.b64encode(data)


def b64decode(data, urlsafe=True):
    """
    Simple wrapper function for decoding base64 string.

    :param data: Data to be decoded. It has to be either bytes or str.
                 If it has a type of str, This will be encoded to bytes.
                 Missing padding characters will be appended.
    :param urlsafe: Determines if data is encoded with base64url. Default value
                    is True.
    :returns: base64 encoded data.
    """
    if isinstance(data, str):
        data = data.encode()
    data += b"="*((4 - len(data) % 4) if len(data) % 4 != 0 else 0)

    if urlsafe:
        return base64.urlsafe_b64decode(data)
    else:
        return base64.b64decode(data)
