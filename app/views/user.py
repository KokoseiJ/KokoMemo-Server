# -*- coding: utf-8 -*-

from flask import request
from flask import Blueprint

import time
import bcrypt
from math import floor

from app import db
from app.module.hash import sha256
from app.module.jwt import jwt_encode, jwt_decode
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
    if request.form.get("email", None) is None:
        return return_data(400, "email not provided.")
    if request.form.get("nickname", None) is None:
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

    issued = floor(time.time())
    expire = issued + 3600
    payload = {
        "iat": issued,
        "exp": expire,
        "username": username,
        "password": hashed_pw,
        "email": email,
        "nickname": nickname
    }
    jwt = jwt_encode(payload)
    print(jwt)

    return return_data(201, "Email has been sent to your account. "
                            "Please use the link provided in email to "
                            "register your account.")


@bp.route('/verify', methods=['POST'])
def verify_register():
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")

    token = auth.split(" ", 1)[1]
    payload = jwt_decode(token)
    if not payload:
        return return_data(403, "JWT signature mismatch.")
    username = payload("username", None)
    password = payload("password", None)
    email = payload("email", None)
    nickname = payload("nickname", None)

    if None in [username, password, email, nickname]:
        return return_data(400, "Invalid token format.")

    user = User(
        username=username,
        password=password,
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

    user.recent_token_issued_time = issued()
    db.session.commit()

    return return_data(201, "Token issued successfully.", {"token": jwt})
