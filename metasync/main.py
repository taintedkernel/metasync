from sqlalchemy.ext.declarative import declarative_base

from datetime import datetime

try: import simplejson as json
except ImportError: import json


class FileMissingError(Exception):
    pass

class InvalidFileError(Exception):
    pass

class NullHashError(Exception):
    pass

class DefaultEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'to_json'):
            return obj.to_json()
        elif isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        else:
           return obj


Base = declarative_base()


