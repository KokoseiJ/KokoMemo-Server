# -*- coding: utf-8 -*-

import time
import bcrypt

from app.module.hash import sha256
from app.module.jwt import jwt_decode

from models import User


def return_data(code: int, message: str = "", data: [list, dict] = None):
    """
    Simple wrapper function for generating a return value that has a format of
    ({'code': code, 'message': message}, code).

    :param code: HTTP Status code
    :param message: Message to be displayed to the user.
    :returns: tuple that has a format of (dict, int) That can be passed to
              flask right away.
    :raises ValueError: If code is not int, It raises ValueError.
    :param data: #TODO: add docstring
    """
    if not isinstance(code, int):
        raise ValueError("code must be integer")

    return {
        "meta": {
            "code": code,
            "message": message
        },
        "data": data
    }, code


def check_login(auth):
    """
    Checks if username and password provided is valid.

    :param auth: werkzeug.datastructures.Authorization. This can be retrieved
                 in flask using request.authorization. It can also be None.
    :returns: 2 If auth is None, User query if auth is valid, False if not.
    """
    if auth is None:
        return 2

    username = auth.username
    password = auth.password
    user_query = User.query.filter_by(username=username).first()
    hashed_pw = user_query.password

    return user_query if bcrypt.checkpw(sha256(password), hashed_pw) else False


def token_to_user(token):
    """
    Retrieves user row from token.
    This function will decode token, check signature and expiration time,
    and retrieve user object.

    :param token: token to be decoded. It must be str.
    :returns: (False, failure_message) If token is not valid.
              (True, User) If token is valid.
    """
    retrived = time.time()
    try:
        payload = jwt_decode(token)
    except ValueError:
        return False, "Token is not in valid JWT format."
    if not payload:
        return False, "Token signature mismatch."

    if payload.get("exp") != retrived:
        return False, "Token is expired."

    user = User.query.filter_by(id=payload.get("userid")).first()

    if user.recent_token_issued_time != payload.get("iat"):
        return False, "Token is expired."

    return True, user
