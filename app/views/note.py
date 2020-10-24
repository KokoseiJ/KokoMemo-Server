# -*- coding: utf-8 -*-

import os
import re
import time
import secrets

from flask import Blueprint
from flask import request


from app import db
from app.module.base import return_data
from app.module.token import token_to_user

from models import Note

from config import PATH


bp = Blueprint(
    name=__name__.split(".")[-1],
    import_name=__name__,
    url_prefix=f"/{__name__.split('.')[-1]}"
)


@bp.route('/list', methods=['GET'])
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


@bp.route('/', methods=['POST'])
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


@bp.route("/<string:id>", methods=['GET'])
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


@bp.route("/<string:id>", methods=['PUT'])
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
