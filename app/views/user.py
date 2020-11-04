# -*- coding: utf-8 -*-

from flask import request
from flask import Blueprint

import time
import bcrypt
from math import floor

from app import db
from app.module.hash import sha256
from app.module.jwt import jwt_encode
from app.module.util import return_data, check_login

from models import User


bp = Blueprint(
    name=__name__.split(".")[-1],
    import_name=__name__,
    url_prefix=f"/{__name__.split('.')[-1]}"
)


@bp.route('/register', methods=['POST'])
def register():
    # TODO: Add E-Mail verification, possibly by making additional endpoint
    if request.authorization is None:
        return return_data(400, "Authorization not provided.")
    if not request.form.get("email", ""):
        return return_data(400, "email not provided.")
    if not request.form.get("nickname", ""):
        return return_data(400, "nickname not provided.")

    username = request.authorization.username
    password = request.authorization.password
    email = request.form.get("email")
    nickname = request.form.get("nickname")

    # Check if user with same username/email already exists
    if User.query.filter_by(username=username).first() is not None:
        return return_data(403, "Username already exists.")
    elif User.query.filter_by(email=email).first() is not None:
        return return_data(403, "Email already used.")

    hashed_pw = bcrypt.hashpw(
        sha256(password),
        bcrypt.gensalt()
    )

    user = User(
        username=username,
        password=hashed_pw,
        email=email,
        nickname=nickname
    )

    db.session.add(user)
    db.session.commit()

    return return_data(201, "Successfully registered!")


@bp.route('/token', methods=['GET'])
def get_token():
    user = check_login(request.authorization)
    if user == 2:
        return return_data(401, "Authorization not provided.")
    elif not user:
        return return_data(401, "Wrong Username or Password.")

    issued = floor(time.time())
    expire = issued + 3600
    payload = {
        "iat": issued,
        "exp": expire,
        "userid": user.id
    }
    jwt = jwt_encode(payload)
    return return_data(201, "Token issued successfully.", {"token": jwt})
