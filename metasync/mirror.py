from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, orm

import click
#import click_log

try: import simplejson as json
except ImportError: import json

from datetime import datetime
import time

import tempfile
import shutil

import logging
import hashlib
import sys
import os
import re

from main import Base, FileMissingError, InvalidFileError, NullHashError, DefaultEncoder


logger = logging.getLogger('metasync')


######################
### Mirror objects ###
######################

class MSMirror(Base):
    __tablename__ = 'mirror'

    id = Column(Integer, primary_key=True)
    type = Column(String(64), nullable=False)
    last_check = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror',
        'polymorphic_on': type
    }

    def __init__(self, host, mtype):
        self.host = host
        self.mtype = mtype

    def walk(self, path):
        pass


class MSMirrorMountedFS(MSMirror):
    __tablename__ = 'mirror_mountedfs'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_fs',
    }

    def __init__(self, host, mtype):
        super().__init(host, mtype)

    def walk(self, path):
        pass


class MSMirrorSFTP(MSMirror):
    __tablename__ = 'mirror_sftp'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)
    host = Column(String(256), nullable=False, unique=True)
    params = Column(String(256))

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_sftp',
    }

    def __init__(self, host, mtype):
        super().__init(host, mtype)

    def walk(self, path):
        pass


class MSMirrorFile(Base):
    __tablename__ = 'mirror_files'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    file = relationship('MSFile', backref='mirrors')
    mirror_id = Column(Integer, ForeignKey('mirror.id'))
    mirror = relationship('MSMirror', backref='files')
    filename = Column(String(256), nullable=False, unique=True)


#
# mirror_sftp
# id=1 host=sftp://user:pass@my.pictures.com/
#
# mirror_fs
# id=2 host=/export/backup/newbackup/
#
# mirror
# id=1 type=sftp
# id=2 type=mountedfs
#
# mirrorfiles
# id=1 file_id=1 mirror_id=1
#
# files
# id=1 filename=/username/pictures/img_0001.jpg
#

