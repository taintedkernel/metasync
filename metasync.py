#!/usr/bin/env python

from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from datetime import datetime
import time

import hashlib
import logging
import sys
import os
import re


Base = declarative_base()

class FileMissingError(Exception):
    pass

class InvalidFileError(Exception):
    pass

class MSFile(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True)
    filename = Column(String(256), nullable=False)
    sha256 = Column(String(1024), default=None)
    last_visit = Column(DateTime)

    def __init__(self, filename, sha256=None, verify=True):
        if verify:
            if not os.path.exists(filename):
                raise InvalidFileError

        self.filename = os.path.basename(filename)

        if verify:
            if self.sha256:
                logger.debug('ignoring provided sha256, recalculating')
            self.sha256 = self.compute_sha256()
        else:
            self.sha256 = sha256

    def __repr__(self):
        return '<{0} sha256={1}>'.format(self.filename, self.sha256[:16])

    def compute_sha256(self, blocksize=65536):
        hasher = hashlib.sha256()
        with open(self.filename, 'rb') as f:
            buf = f.read(blocksize)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(blocksize)
            return hasher.digest()

    # Visit the file
    # This is verification the file still exists at the
    # same location, with the same contents
    def visit(self, strong=False):
        if not os.path.exists(self.filename):
            logger.warning('{0} missing'.format(self))
            raise FileMissingError

        modified = False
        mtime = datetime.fromttimestamp(os.path.getmtime(self.filename))
        ctime = datetime.fromttimestamp(os.path.getctime(self.filename))
        if mtime > self.last_visit:
            modified = True
        if ctime > self.last_visit:
            modified = True

        if modified or strong:
            sha256 = self.compute_sha256(self.filepath)
            if sha256 != self.sha256:
                logger.info('{0} contents updated to {1}'.format(self, sha256))
                self.sha256 = sha256
                return True
            else:
                logger.debug('{0} detected as updated but contents unchanged'.format(self))

        return False



class MSManager(object):
#    tablename__ = "manager"
#    id = Column(Integer, primary_key=True)

    def __init__(self):
        # TODO: load database, initialize
        engine = create_engine('sqlite:///metasync.db')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.sasession = Session()

        # TODO: check ignore list from db
        self.ignore_files = list()

        # TODO: load file lists from db
        self.files = self.sasession.query(MSFile).all()
        self.missing_files = list()
        self.verify_db()

    # Verify internal list of files
    def verify_db(self):
        logger.info('verifying database')
        for msfile in self.files:
            result = None
            try:
                result = msfile.visit()
            except FileMissingError:
                self.missing_files.append(msfile)

            if result:
                self.sasession.add(msfile)
                self.sasession.commit()

    # Add a file to DB
    def add_file(self, filepath):
        logger.debug('creating new file at {0}'.format(filepath))
        new_file = MSFile(filepath)
        logger.info('created new {0}'.format(new_file))
        self.sasession.add(new_file)
        self.sasession.commit()
        self.files.append(new_file)

    # Check to see if file exists in DB
    def check_exists(self, filepath):
        # TODO: Do we scan DB directly instead?
        if [f for f in self.files if f.filepath == filepath]:
            return True
        return False

    # Check if file is eligable for adding to DB
    # Consists of several checks:
    #  - Is it in ignore list?
    def check_file(self, filepath):
        # Abort on first failure
        for regex in self.ignore_files:
            if re.match(regex, filepath):
                return False

        # TODO: check other things here
        # If passes all, then good for adding
        return True

    # Walk through directory structure, searching for new files
    def scan_path(self, path):
        logger.info('scanning for new files')

        for root, dirs, files in os.path.walk(path):
            logger.debug("descending into {0}", root)
            for name in files:
                filepath = os.path.join(root, name)

                if self.check_exists(filepath):
                    continue

                logger.info("checking {0}", filepath)
                if self.check_file(filepath):
                    self.new_files.append(filepath)

        if self.new_files:
            for filename in self.new_files:
                # TODO: reconcile with self.missing
                self.add_file(filepath)


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

mgr = MSManager()






