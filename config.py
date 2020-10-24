# -*- coding: utf-8 -*-

import os


PATH = os.path.dirname(__file__)

# SQL Server info
SQLALCHEMY_DATABASE_URI = f"sqlite:///{PATH}/data.db"
SQLALCHEMY_TRACK_MODIFICATIONS = False

SECRET_KEY = b"test-secret-key"
