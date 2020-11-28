# -*- coding: utf-8 -*-

from flask import request
from flask import Blueprint

import os
import re
import json
import time
import secrets

from app import db
from app.module.b64 import check_b64, b64decode
from app.module.util import return_data, token_to_user

from config import PATH
from models import Note


def get_list(path):
    '''
    return [json.loads(read_file(file.path)) if file.is_file()
            else {
                "title": file.name,
                "type": "D",
                "content": get_list(file.path),
                "version": None
            } for file in os.scandir(path) if check_b64(file.name[1:])]
    '''
    filelist = []
    for file in os.scandir(path):
        if file.name[0] == "_" or not check_b64(file.name[1:]):
            continue
        if file.is_file():
            with open(file.path) as f:
                data = json.load(f)
            data.pop("contents")
            filelist.append(data)
        else:
            with open(os.path.join(file.path, "_title")) as f:
                title = f.read()
            filelist.append({
                "title": title,
                "type": "D",
                "preview": None,
                "content": get_list(file.path),
                "version": None
            })
    return filelist


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
        return return_data(403, user)

    data = get_list(os.path.join(PATH, "notes", str(user.id)))

    return return_data(200, data=data)


@bp.route('/<path:note_path>', methods=['POST'])
def upload_note(note_path):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    data = request.get_json()
    if data is None:
        data = request.form
        if data is None:
            return return_data(400, "Data not provided.")

    title = data.get("title", "")
    _type = data.get("type", "")
    content = data.get("content", "")

    id_list_path = os.path.join(PATH, "notes", str(user.id), "_id_list")
    with open(id_list_path) as f:
        id_list = f.read().split(",")

    if False in [check_b64(path) and path in id_list
                 for path in note_path.split("/")]:
        return return_data(400, "Path is invalid.")
    if not title:
        return return_data(400, "Title not provided.")
    if len(title) >= 50:
        return return_data(400, "Title is too long.")
    if _type not in ["N", "F", "D"]:
        return return_data(400, "Wrong type specified.")
    if _type in ["N", "F"] and not content:
        return return_data(400, "Content not provided.")

    try:
        user_path = os.path.join(PATH, "notes", str(user.id))
        os.mkdir(user_path)
    except FileExistsError:
        if os.path.isfile(user_path):
            return return_data(500, "Failed to create a user folder.\n"
                                    "This is server-side error and "
                                    "should not happen at all.\n"
                                    "Please contact administartor for help.")
    except PermissionError:
        return return_data(500, "Failed to create a user folder.\n"
                                "This is server-side error and "
                                "should not happen at all.\n"
                                "Please contact administartor for help.")

    while True:
        id = _type + secrets.token_urlsafe(8)
        if id not in id_list:
            break

    if _type == "D":
        try:
            fpath = os.path.join(user_path, note_path, id)
            os.mkdir(fpath)
        except (FileExistsError, PermissionError):
            return return_data(500, "Failed to create a folder.\n"
                                    "This is server-side error and "
                                    "should not happen at all.\n"
                                    "Please contact administrator for help.")
        with open(os.path.join(fpath, "_name"), "w") as f:
            f.write(title)
    else:
        version = secrets.token_hex(4) if _type in ["N", "F"] else None
        if _type == "N":
            body_strip = re.sub("\\s", " ", content)
            preview = body_strip if len(body_strip) <= 50 \
                else body_strip[:47] + "..."
        elif _type == "F":
            preview = None
        data = {
            "title": title,
            "type": _type,
            "preview": preview,
            "content": content,
            "version": version
        }
        with open(os.path.join(user_path, note_path, id), "w") as f:
            f.write(json.dumps(data))

    with open(id_list_path, "a") as f:
        f.write(id + ",")

    return return_data(201, "Successfully uploaded!")


@bp.route("/<string:id>", methods=['GET'])
def get_note(id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

    if id not in [note.id for note in user.notes]:
        return return_data(404, "Note with given id doesn't exist.")

    with open(os.path.join(PATH, "notes", str(user.id), id)) as f:
        return return_data(200, data=f.read())


@bp.route("/<string:id>", methods=['PUT'])
def edit_note(id):
    auth = request.headers.get("Authorization", str())
    if not auth.strip().startswith("Bearer "):
        return return_data(401, "Authorization not provided.")
    token = auth.split(" ", 1)[1]
    is_valid, user = token_to_user(token)
    if not is_valid:
        return return_data(403, user)

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
