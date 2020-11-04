# -*- coding: utf-8 -*-

import json

from app.module.hash import hmacsha256
from app.module.b64 import b64encode, b64decode

from config import SECRET_KEY


def jwt_encode(payload, secret=SECRET_KEY):
    """
    Simple JWT token generator.
    This function signs the token using HMAC SHA256 algorithm.

    :param payload: Payload to be inserted in token, Should be dict.
    :param secret: Secret key to sign the token.
                   Default value is app.secret_key.
    :returns: New JWT token in str.
    """
    jwt_header = b64encode(b'{"alg":"HS256","typ":"JWT"}')
    jwt_payload = b64encode(json.dumps(payload).encode())

    jwt_header = jwt_header.decode().replace("=", "")
    jwt_payload = jwt_payload.decode().replace("=", "")

    jwt_sig = b64encode(hmacsha256(jwt_header+"."+jwt_payload, secret))
    jwt_sig = jwt_sig.decode().replace("=", "")

    return f"{jwt_header}.{jwt_payload}.{jwt_sig}"


def jwt_decode(token, secret=SECRET_KEY):
    """
    Simple JWT token decoder.
    This function only supports HMAC SHA256 signed token.

    :param token: Token to be decoded. should be str.
    :param secret: Secret key to sign the token.
                   Default value is app.secret_key.
    :returns: dict containing payload if token is valid.
              False If signature is not valid.
    :raises ValueError: If token is not in valid JWT format.
    """
    jwt_split = token.split(".")
    if len(jwt_split) != 3:
        raise ValueError("Not a valid JWT token.")

    jwt_header = json.loads(b64decode(jwt_split[0]).decode())
    jwt_payload = json.loads(b64decode(jwt_split[1]).decode())
    jwt_sig = jwt_split[2]

    if jwt_header.get("typ", None) != "JWT":
        raise ValueError("Not a valid JWT token.")
    elif jwt_header.get("alg", None) != "HS256":
        return False

    jwt_sigcheck = b64encode(
        hmacsha256(
            token.rsplit(".", 1)[0], secret)
    ).decode().replace("=", "")

    return jwt_payload if jwt_sig == jwt_sigcheck else False
