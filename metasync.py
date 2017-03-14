#!/usr/bin/env python

from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

import click

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
    size = Column(Integer)
    ctime = Column(DateTime)
    mtime = Column(DateTime)
    sha256 = Column(String(64), default=None)
    added_time = Column(DateTime)
    last_visit = Column(DateTime)

    def __init__(self, filename, sha256=None, verify=True):
        if verify:
            if not os.path.exists(filename):
                raise InvalidFileError

        #self.filename = os.path.basename(filename)
        self.filename = filename

        if verify:
            if self.sha256:
                logger.debug('ignoring provided sha256, recalculating')
            self.sha256 = self.compute_sha256()
        else:
            self.sha256 = sha256

        now = datetime.now()
        self.ctime = self.get_ctime()
        self.mtime = self.get_mtime()
        self.size = self.get_size()
        self.last_visit = now
        self.added_time = now

    def __repr__(self):
        return '<{0} sha256={1}>'.format(self.filename, self.sha256[:16])

    @property
    def file_name(self):
        return os.path.basename(self.filename)

    @property
    def file_path(self):
        return os.path.dirname(self.filename)

    def get_size(self):
        return os.path.getsize(self.filename)

    def get_ctime(self):
        return datetime.fromtimestamp(os.path.getctime(self.filename))

    def get_mtime(self):
        return datetime.fromtimestamp(os.path.getmtime(self.filename))

    # Compute our file hash
    def compute_sha256(self, blocksize=65536):
        hasher = hashlib.sha256()
        with open(self.filename, 'rb') as f:
            buf = f.read(blocksize)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(blocksize)
            return hasher.hexdigest()

    #
    # Visit the file
    #
    # This is verification the file still exists at the
    # same location, with the same contents.  Metadata
    # changes are not considered a change.
    #
    # Return True if contents modified, False otherwise
    #
    # Decision tree:
    #
    # file exists in same path:
    #   mtime, size (+assume hash) modified - file saved
    #   mtime modified - file saved with same data
    # file missing:
    #   mark as missing, reconcile with "new" files at the end
    #
    #
    # - Check if mtime or size modified
    #  - If changed (file was saved) then mark file
    #      as "updated" and possibly update db info
    #  - If size unchanged (file touched/saved with same data)
    #
    #
    def visit(self, strong_verify=False):
        if not os.path.exists(self.filename):
            logger.warning('%s missing', self)
            raise FileMissingError

        modified = False
        #ctime = self.get_ctime()
        #if ctime > self.last_visit:
        #    modified = True

        mtime = self.get_mtime()
        if mtime > self.last_visit:
            modified = True

        size = self.get_size()
        if size != self.size:
            modified = True

        #
        # If file timestamps modified or we want
        # a byte-level verification, then recompute hash
        #
        # TODO: Need logic to determine if completely new file.
        #   May need to prompt user.
        #
        if modified or strong_verify:
            sha256 = self.compute_sha256()
            if sha256 != self.sha256:
                logger.info('%s contents updated to %s', self, sha256)
                self.sha256 = sha256
                return True
            else:
                logger.debug('%s detected as updated but contents unchanged', self)

        return False

    #
    # Update the file
    #
    # This will update metadata about the file.
    # Takes current information as new source-of-truth
    #
    # stong=True recomputes file contents in addition to metadata
    #
    def update(self, strong=False):
        self.ctime = self.get_ctime()
        self.mtime = self.get_mtime()
        self.size = self.get_size()
        if strong:
            self.sha256 = self.compute_sha256()



class MSManager(object):
#    tablename__ = "manager"
#    id = Column(Integer, primary_key=True)

    def __init__(self, verify=True):
        # TODO: load database, initialize
        engine = create_engine('sqlite:///metasync.db')
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.sasession = Session()

        # TODO: check ignore list from db
        self.ignored_files = list()

        # TODO: load file lists from db
        self.existing_files = self.sasession.query(MSFile).all()
        self.missing_files = list()
        if verify:
            self.verify_db()

    # Verify internal list of files
    # TODO: stuff
    def verify_db(self):
        logger.info('verifying database')
        for msfile in self.existing_files:
            result = None
            logger.debug('visiting %s', msfile.filename)
            try:
                result = msfile.visit()
            except FileMissingError:
                self.missing_files.append(msfile)

            if result:
                self.sasession.add(msfile)
                self.sasession.commit()

    # Add a file to DB
    def add_file(self, filepath, delay_commit=False):
        logger.debug('adding new file at %s', filepath)
        new_file = MSFile(filepath)
        logger.info('added %s', new_file)
        self.sasession.add(new_file)
        if not delay_commit:
            self.sasession.commit()
        self.existing_files.append(new_file)

    # Check to see if file exists in DB
    def get_file_db(self, path):
        # TODO: Do we scan DB directly instead?
        filtered_files = sorted(filter(lambda x: x.filename == path, self.existing_files), key=lambda y: y.added_time)
        if len(filtered_files) == 0:
            return None
        elif len(filtered_files) == 1:
            pass
        else:
            logger.error('multiple files returned on match for %s, returning most recent:', path)
            for f in filtered_files:
                logger.error('  %s', f)
        return filtered_files.pop()

    # Check if file is eligable for adding to DB
    # Consists of several checks:
    #  - Is it in ignore list?
    def check_file_eligable(self, filepath):
        # Abort on first failure
        for regex in self.ignored_files:
            if re.match(regex, filepath):
                return False

        # TODO: check other things here
        # If passes all, then good for adding
        return True

    #
    # Scan a path
    #
    # - Search for new files
    # - Verify existing files
    #
    def scan_path(self, path):
        logger.info('scanning path %s', path)
        files_parsed = 0
        new_files = list()
        known_files = self.existing_files

        for root, dirs, files in os.walk(path):
            logger.debug('descending into %s: %d files, %d directories found', root, len(files), len(dirs))
            for name in files:
                filename = os.path.join(root, name)
                logger.info('checking [%d/%d]: %s', files_parsed+1, len(files), filename)

                existing_file = self.get_file_db(filename)
                if existing_file:
                    # TODO: files being visited twice, once on init with verify_db, and then now
                    existing_file.visit()
                else:
                    new_files.append(filename)

                files_parsed += 1

        for filename in new_files:
            # TODO: reconcile with self.missing
            if self.check_file_eligable(filename):
                self.add_file(filename, delay_commit=True)

        self.sasession.commit()



@click.group()
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
def cli():
    pass

@cli.command()
@click.option('--path', default=os.getcwd(), help='root path for files to manage')
def scan(path):
    mgr.scan_path(path)



logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

mgr = MSManager()


if __name__ == '__main__':
    scan()

