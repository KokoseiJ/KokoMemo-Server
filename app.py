from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

import os
import re
import hmac
import json
import time
import base64
import bcrypt
import hashlib
import secrets
from math import floor

PATH = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{PATH}/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.secret_key = base64.b64encode(b"testsecretkey")


class User(db.Model):
    id = db.Column(db.Integer, unique=True, nullable=False, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    nickname = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'


class Note(db.Model):
    id = db.Column(
        db.String(11), unique=True, nullable=False, primary_key=True)
    title = db.Column(db.String(50), nullable=False)
    preview = db.Column(db.String(50), nullable=False)
    created_time = db.Column(db.BigInteger, nullable=False)
    edited_time = db.Column(db.BigInteger, nullable=True)
    version = db.Column(db.String(8), nullable=False)
    user_id = db.Column(
        db.String(50), db.ForeignKey("user.id"), nullable=False)
    user = db.relationship('User', backref=db.backref('notes', lazy=True))

    def __repr__(self):
        return f'<Note {self.id}:{self.user.username}>'


def return_data(code, message="", data=None):
    """
    Simple wrapper function for generating a return value that has a format of
    ({'code': code, 'message': message}, code).

    :param code: HTTP Status code
    :param message: Message to be displayed to the user.
    :returns: tuple that has a format of (dict, int) That can be passed to
              flask right away.
    :raises ValueError: If code is not int, It raises ValueError.
    """
    if not isinstance(code, int):
        raise ValueError("code must be integer")
    if data is None:
        return {
            'meta': {
                'code': code,
                'message': message
            }
        }, code
    else:
        return {
            'meta': {
                'code': code,
                'message': message
            },
            'data': data
        }, code


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


def sha256(password):
    """
    Simple wrapper function for hashing password using SHA256 algorithm.

    :param password: Password to be hashed. It has to be either bytes or str.
                     If it has a type of str, This will be encoded to bytes.
    :returns: base64 encoded SHA256 hashed password in bytes.
    """
    if isinstance(password, str):
        password = password.encode()
    return b64encode(hashlib.sha256(password).digest(), False)


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


def hmacsha256(data, key):
    """
    Simple wrapper function for generating HMAC SHA256 signature.
    :param data: data to be hashed. It has to be either bytes or str.
                 If it has a type of str, This will be encoded to bytes.
    :returns: HMAC SHA256 signed data in bytes.
    """
    if isinstance(data, str):
        data = data.encode()
    return hmac.digest(key, data, hashlib.sha256)


def jwt_encode(payload, secret=app.secret_key):
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


def jwt_decode(token, secret=app.secret_key):
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
        hmacsha256(token.rsplit(".", 1)[0], secret)).decode().replace("=", "")

    return jwt_payload if jwt_sig == jwt_sigcheck else False


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


@app.route('/')
def mukuro():
    return 'Mukuro Ikusaba, the 16th Student, ' \
           'lying hidden somewhere in this school... ' \
           'the one they call the Ultimate Despair, ' \
           'Watch out for her.'


@app.route('/user/register', methods=['POST'])
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

    hashed_pw = bcrypt.hashpw(sha256(password), bcrypt.gensalt())
    user = User(
        username=username, password=hashed_pw, email=email, nickname=nickname)
    db.session.add(user)
    db.session.commit()

    return return_data(201, "Successfully registered!")


@app.route('/user/token', methods=['GET'])
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


@app.route('/note/list', methods=['GET'])
def get_note_list():
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Auhorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(401, user)

    data = [note.__dict__ for note in user.notes]
    for dict in data:
        dict.pop('_sa_instance_state', None)
    return return_data(200, data=data)


@app.route('/note', methods=['POST'])
def upload_note():
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer"):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(401, user)

    title = request.form.get("title", "")
    body = request.form.get("body", "")

    if not title:
        return return_data(400, "Title not provided.")
    if len(title) >= 50:
        return return_data(400, "Title is too long.")

    body_strip = re.sub("\\s", " ", body)

    preview = body_strip if len(body_strip) <= 50 \
        else body_strip[:47] + "..."

    id_list = [note.id for note in user.notes]
    id = secrets.token_urlsafe(8)
    while id in id_list:
        id = secrets.token_urlsafe(8)
    version = secrets.token_hex(4)

    if not os.path.isdir(os.path.join(PATH, "notes")):
        try:
            os.mkdir(os.path.join(PATH, "notes"))
        except OSError:
            return return_data(500, "Cannot create 'notes' folder. This "
                                    "is server configuration error and "
                                    "should not happen.")
    if not os.path.isdir(os.path.join(PATH, "notes", str(user.id))):
        try:
            os.mkdir(os.path.join(PATH, "notes", str(user.id)))
        except OSError:
            return return_data(500, "Cannot create user folder. This "
                                    "is server configuration error and "
                                    "should not happen.")
    with open(os.path.join(PATH, "notes", str(user.id), id), "w") as f:
        f.write(body)

    note = Note(id=id, title=title, preview=preview, version=version,
                created_time=time.time())
    user.notes.append(note)
    db.session.add(note)
    db.session.commit()

    return return_data(201, "Successfully uploaded!")


@app.route("/note/<id>", methods=['GET'])
def get_note(id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer"):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(401, user)

    if id not in [note.id for note in user.notes]:
        return return_data(404, "Note with given id doesn't exist.")

    with open(os.path.join(PATH, "notes", str(user.id), id)) as f:
        return return_data(200, data=f.read())


@app.route("/note/<id>", methods=['PUT'])
def edit_note(id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer"):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(401, user)

    if id not in [note.id for note in user.notes]:
        return return_data(404, "Note with given id doesn't exist.")

    title = request.form.get("title", "")
    body = request.form.get("body", "")
    uploaded_version = request.form.get("version", "")

    if not title:
        return return_data(400, "Title not provided.")
    if len(title) >= 50:
        return return_data(400, "Title is too long.")
    if not uploaded_version:
        return return_data(400, "version not provided.")

    body_strip = re.sub("\\s", " ", body)

    preview = body_strip if len(body_strip) <= 50 \
        else body_strip[:47] + "..."

    note = Note.query.filter_by(user_id=user.id, id=id).first()

    version = secrets.token_hex(4)
    while uploaded_version == version or note.version == version:
        version = secrets.token_hex(4)

    if uploaded_version == note.version:
        with open(os.path.join(PATH, "notes", str(user.id), id), "w") as f:
            f.write(body)
    else:
        with open(os.path.join(PATH, "notes", str(user.id), id), "a") as f:
            f.write("\n--------On this computer--------\n")
            f.write(body)

    note.title = title
    note.preview = preview
    note.version = version
    note.edited_time = time.time()

    db.session.commit()

    return return_data(201, "Successfully uploaded!")


db.create_all()
app.run()
