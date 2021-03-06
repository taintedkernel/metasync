from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime, UniqueConstraint
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


class InvalidFileError(Exception):
    def __init__(self, filename):
        super(Exception, self).__init__(filename)
        self.filename = filename

    def __str__(self):
         return "File {0} not found".format(self.filename)


###################
### File object ###
###################

# TODO subclass these to allow "root" files to be remote
class MSFile(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    repo_id = Column(Integer, ForeignKey('repos.id'))
    repo = relationship('MSRepo', backref='files')
    filename = Column(String(256), nullable=False)
    status = Column(String(64), default='valid')  # valid, missing
    size = Column(Integer, default=0)
    mtime = Column(DateTime)
    ctime = Column(DateTime)
    sha256 = Column(String(64), default=None)
    last_visit = Column(DateTime)

    UniqueConstraint('filename', 'repo')

    # TODO: Do we really need functionality to specify a custom sha256?
    # Maybe in cases where we are trying to recover from corruption?
    # Also, might want to support a "lite" mode where files are not hashed
    # FYI Sqlalchemy utilizes __new__ (not __init__)
    def __init__(self, filename, repo, sha256=None, verify_exist=True, compute_hash=True):
        self.filename = filename
        self.repo = repo

        if verify_exist:
            if not os.path.exists(self.local_file_path):
                raise InvalidFileError(self.local_file_path)

        if compute_hash:
            if self.sha256:
                logger.debug('ignoring provided sha256, recalculating')
            self.sha256 = self.compute_sha256()
        else:
            if not sha256:
                logger.error('unable to create file with null hash!')
                raise NullHashError
            self.sha256 = sha256

        now = datetime.now()
        self.mtime = self.get_mtime()
        self.ctime = self.get_ctime()
        self.size = self.get_size()
        self.last_visit = now

    def __repr__(self):
        #return '<{0} mtime={1} size={2} sha256={3} last_visit={4} added={5}>'\
        #        .format(self.filename, self.mtime, self.size, self.sha256[:16],\
        #                self.last_visit, self.added_time)
        if self.added_time:
            return '<File {0} repo={7} name={1} mtime={2} size={3} sha256={4} added={6} last_visit={5}>'.format(
                   self.id, self.filename, self.mtime.strftime('%Y-%m-%d %H:%M:%S'), self.size, self.sha256[:16],
                   self.last_visit.strftime('%Y-%m-%d %H:%M:%S'), self.added_time.strftime('%Y-%m-%d %H:%M:%S'), self.repo_id)
        else:
            return '<File {0} repo={6} name={1} mtime={2} size={3} sha256={4} last_visit={5}>'.format(
                   self.id, self.filename, self.mtime.strftime('%Y-%m-%d %H:%M:%S'), self.size, self.sha256[:16],
                   self.last_visit.strftime('%Y-%m-%d %H:%M:%S'), self.repo_id)

    def to_json(self):
        serial = dict()
        serial['filename'] = self.filename
        serial['sha256'] = self.sha256
        serial['size'] = self.size
        serial['mtime'] = self.mtime.strftime('%Y-%m-%d %H:%M:%S')
        serial['ctime'] = self.ctime.strftime('%Y-%m-%d %H:%M:%S')
        #if self.added_time:
        #    serial['added_time'] = self.added_time.strftime('%Y-%m-%d %H:%M:%S')
        serial['last_visit'] = self.last_visit.strftime('%Y-%m-%d %H:%M:%S')
        return json.dumps(serial)

    # Get the filename without path
    @property
    def file_name(self):
        return os.path.basename(self.filename)

    # Path of filename below repo base
    @property
    def file_directory(self):
        return os.path.join(os.path.dirname(self.filename), '')

    # Full path: base repo path + filename
    @property
    def local_file_path(self):
        return os.path.join(self.repo.path, self.filename)

    # TODO: Still kinda broke, fix this
    @property
    def added_time(self):
        if len(self.history) == 0:
            return None
        added_hist = filter(lambda x: x.status == 'new', self.history)
        # displaying history is an issue, hits recursion limit #
        #logger.debug('in added_time, data=%s', added_hist)
        return None
        return datetime.now()
    #    if len(added_hist) == 1:
    #        return added_hist.pop().timestamp
    #    elif len(added_hist) == 0:
    #        logger.error('file %s has no \'new\' history, returning null added time', self)
    #    elif len(added_hist) > 1:
    #        logger.error('file %s has multiple \'new\' histories, returning null added time', self)
    #    return None

    def get_size(self):
        return os.path.getsize(self.local_file_path)

    def get_mtime(self):
        return datetime.fromtimestamp(os.path.getmtime(self.local_file_path))

    # We won't typically use this, but tracking regardless
    def get_ctime(self):
        return datetime.fromtimestamp(os.path.getctime(self.local_file_path))

    # Compute our file hash
    def compute_sha256(self, blocksize=65536):
        hasher = hashlib.sha256()
        with open(self.local_file_path, 'rb') as f:
            buf = f.read(blocksize)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(blocksize)
            return hasher.hexdigest()

    def show_history(self):
        for h in sorted(self.history, key=lambda x: x.timestamp):
            logger.debug('%s', h)

    # Return data at specific timestamp
    def get_history_ts(self, ts):
        h_id = 0
        logger.debug('checking for history of %s at time %s', self, ts)
        while True:
            logger.debug('found history %s', self.history[h_id])
            if h_id + 1 >= len(self.history) or self.history[h_id + 1].timestamp > ts:
                break
            h_id += 1
        return self.history[h_id].data

    def build_fn_diff(self, start):
        logger.info('checking %s', self)
        history = sorted(self.history, key=lambda x: x.timestamp)
        for idx, hist in enumerate(history):
            if hist.timestamp > start:
                break
        start_fn = history[max(idx - 1, 0)].data['filename']
        current_fn = self.filename
        if start_fn != current_fn:
            logger.info('file %s previously named %s at %s', current_fn, start_fn, start)
        return (current_fn, start_fn)

    #
    # Visit the file
    #
    # This is verification the file still exists at the
    # same location, with the same contents (unchanged).
    # Metadata changes are not considered a change.
    #
    # Return True if contents modified, False otherwise
    #
    def visit(self, strong_verify=False):
        if not os.path.exists(self.local_file_path):
            ### UNIT TEST ###
            logger.warning('%s missing', self.filename)
            ### END ###
            raise FileMissingError

        modified = dict()
        #ctime = self.get_ctime()
        #if ctime > self.last_visit:
        #    modified = True

        mtime = self.get_mtime()
        #logger.debug('last visit: %s' % self.last_visit)
        #logger.debug('mtime: %s' % mtime)
        if mtime > self.last_visit:
            modified['mtime'] = mtime
            ### UNIT TEST ###
            logger.info('%s mtime modified', self.filename)
            ### END ###

        self.last_visit = datetime.now()

        size = self.get_size()
        if size != self.size:
            modified['size'] = size
            logger.info('%s size modified', self.filename)

        #
        # If file timestamps modified or we want
        # a byte-level verification, then recompute hash
        #
        # TODO: Need logic to determine if completely new file.
        #   May need to prompt user.
        #
        if len(modified) > 0 or strong_verify:
            sha256 = self.compute_sha256()
            if sha256 != self.sha256:
                ### UNIT TEST ###
                logger.info('%s contents updated to %s', self.filename, sha256)
                ### END ###

                if len(modified) == 0:
                    logger.fatal('possible data corruption on %s, contents changed without metadata change!', self.filename)
                    logger.error('manual investigation required, not updating database')
                    return None

                self.sha256 = modified['sha256'] = sha256
            else:
                ### UNIT TEST ###
                logger.info('%s detected as updated but contents unchanged, updating metadata', self)
                ### END ###

            return modified
        return None

    #
    # Refresh the file
    #
    # This will update metadata about the file.
    # Takes current information as new source-of-truth.
    #
    # stong=True recomputes file contents in addition to metadata
    #
    def refresh(self, strong=False):
        self.ctime = self.get_ctime()
        self.mtime = self.get_mtime()
        self.size = self.get_size()
        if strong:
            self.sha256 = self.compute_sha256()

    #
    # Update the file
    #
    # This updates the file with data given in a dictionary
    #
    def update(self, data):
        for k, v in data.iteritems():
            setattr(self, k, v)
