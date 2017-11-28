from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, orm

import click
#import click_log

try:
    import simplejson as json
except ImportError:
    import json

from datetime import datetime
import time

import tempfile
import shutil

import logging
import hashlib
import sys
import os
import re

from main import Base, FileMissingError, NullHashError, DefaultEncoder


logger = logging.getLogger(__name__)


class MSRepo(Base):
    __tablename__ = 'repos'

    id = Column(Integer, primary_key=True)
    path = Column(String(256), nullable=False)
    status = Column(String(64))
    date_added = Column(DateTime, default=datetime.now())

    def __init__(self, path):
        self.path = path
        self.status = 'new'
