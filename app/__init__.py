#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()


def create_app():
    app = Flask(__name__)

    import config
    app.config.from_object(obj=config)

    db.init_app(app)
    migrate.init_app(app, db)

    try:
        from os import mkdir
        from config import FILE_PATH
        mkdir(FILE_PATH)
    except FileExistsError:
        pass

    import models
    from app import views

    for module in [views.__getattribute__(attr) for attr in dir(views)
                   if not attr.startswith("_")]:
        try:
            app.register_blueprint(
                blueprint=module.__getattribute__("bp")
            )
        except AttributeError:
            print(f"'{module.__name__}' is not a valid viewpoint.")

    return app
