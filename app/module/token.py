# -*- coding: utf-8 -*-

import time

from app.module.jwt import jwt_decode

from models import User


def token_to_user(token):
    """
    Retrieves user row from token.
    This function will decode token, check signature and expiration time,
    and retrieve user object.

    :param token: token to be decoded. It must be str.
    :returns: (False, failure_message) If token is not valid.
              (True, User) If token is valid.
    """
    try:
        payload = jwt_decode(token)
    except ValueError:
        return False, "Token is not in valid JWT format."
    if not payload:
        return False, "Token signature mismatch."

    if payload.get("exp") <= time.time():
        return False, "Token is expired."

    return True, User.query.filter_by(id=payload.get("userid")).first()
