# -*- coding: utf-8 -*-

import bcrypt

from app.module.hash import sha256

from models import User


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
