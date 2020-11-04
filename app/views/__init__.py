import os
path = os.path.dirname(__file__)
__all__ = [name[:-3] for name in os.listdir(path)
           if name.endswith(".py") and not name.startswith("_")]

from app.views import *

del os, path
