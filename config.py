# -*- coding: utf-8 -*-

import os
import base64


PATH = os.path.dirname(__file__)

FILE_PATH = os.path.join(PATH, "files")

# SQL Server info
SQLALCHEMY_DATABASE_URI = f"sqlite:///{PATH}/data.db"
SQLALCHEMY_TRACK_MODIFICATIONS = False

SECRET_KEY = base64.b64decode(os.environ.get('SECRET_KEY'))
