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

    from importlib import import_module
    import_module("models")

    import os
    for m in os.listdir(os.path.join("app", "views")):
        if not m.startswith("__") and m.endswith(".py"):
            module = import_module(
                name=f"app.views.{m.split('.py')[0]}"
            )

            try:
                app.register_blueprint(
                    blueprint=module.__getattribute__("bp")
                )
            except AttributeError:
                print(f"'{m.split('.py')[0]}' is not view point")

    return app
