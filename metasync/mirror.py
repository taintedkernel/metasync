from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, orm
import sqlalchemy_jsonfield

from paramiko import SSHClient, AutoAddPolicy
from stat import S_ISDIR

import dateparser

try:
    import simplejson as json
except ImportError:
    import json

from datetime import datetime
import time

import tempfile
import urlparse
import ftplib

import logging
import shlex
import sys
import os
import re

from main import Base, FileMissingError, NullHashError, DefaultEncoder


logger = logging.getLogger(__name__)
plogger = logging.getLogger('paramiko.transport')
plogger.setLevel(logging.INFO)


######################
### Mirror objects ###
######################


def build_mirror(location, params):
    mirror = None
    res = urlparse.urlparse(location)
    if res.scheme == 'file':
        mirror = MSMirrorFS(location, params)
    elif res.scheme == 'ftp':
        mirror = MSMirrorFTP(location, params)
    elif res.scheme == 'sftp':
        mirror = MSMirrorSFTP(location, params)
    else:
        raise InvalidSchemeError

    logger.debug('created new mirror %s', mirror)
    return mirror


class InvalidSchemeError(Exception):
    pass

class InvalidPathError(Exception):
    def __init__(self, filename):
        super(Exception, self).__init__(filename)
        self.filename = filename

    def __str__(self):
         return "Path {0} not found".format(self.filename)

class MissingCredentialsError(Exception):
    pass

class MSMirror(Base, json.JSONEncoder):
    __tablename__ = 'mirror'

    id = Column(Integer, primary_key=True)
    type = Column(String(64), nullable=False)
    url = Column(String(256), nullable=False, unique=True)
    last_check = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror',
        'polymorphic_on': type
    }

    def __repr__(self):
        return '<MSMirror %s type=%s>' % (self.url, self.type)

    def urlparse(self, url):
        p_url = dict()
        res = urlparse.urlparse(url)
        p_url['scheme'] = res.scheme
        p_url['host'] = res.hostname
        p_url['path'] = res.path or '/'

        if hasattr(self, 'DEFAULT_PORT'):
            p_url['port'] = res.port or self.DEFAULT_PORT
            p_url['user'] = res.username or 'anonymous'
            p_url['pass'] = res.password or ''

        #logger.debug('parsed URL: {scheme}://{host}:{port}{path}, user={user}, pass={pass}'.format(**p_url))
        #logger.debug('parsed URL: %s', urlparse.urlunparse(res))
        return p_url

    def connect(self, url):
        logger.debug('connecting to %s', url)

    def test_walk(self, path):
        for mpath, mdirs, mfiles in self.walk(path):
            for mfile in mfiles:
                logger.info('found mirror file %s', mfile)


class MSMirrorFS(MSMirror):
    __tablename__ = 'mirror_fs'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)
    #path = Column(String(256), nullable=False, unique=True)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_fs',
    }

    def __init__(self, url):
        p_url = self.urlparse(url)
        if p_url['scheme'] != 'file':
            raise InvalidSchemeError
        if p_url['host'] != None and p_url['host'] != 'localhost':
            raise InvalidSchemeError

        logger.info('connecting to %s', url)
        self.url = self.connect(p_url['path'])

    def connect(self, url=None):
        url = url or self.url
        super(MSMirrorFS, self).connect(url)
        nurl = os.path.normpath(url)
        if not os.path.isdir(nurl):
            raise InvalidPathError(nurl)
        return nurl

    def walk(self):
        logger.info('scanning path %s', self.url)
        #files_parsed = files_skipped = total_files = 0
        #new_files = list()
        #known_files = self.existing_files

        # Walk through filesystem
        # Iterate over files, checking if new or existing
        # Store in a temporary array
        for root, dirs, files in os.walk(self.url):
            logger.debug('descending into %s: %d files, %d directories found', root, len(files), len(dirs))
            #total_files += len(files)
            #l_files_parsed = 0

            for name in files:
                #if files_parsed % 10 == 0 and files_parsed > 0:
                #    logger.debug('status: %d skipped, %d new, %d parsed, %d total (%2.0f%% complete)',
                #                 files_skipped, len(new_files), files_parsed, total_files, l_files_parsed / float(len(files)) * 100)

                filename = os.path.join(root, name)
                #logger.info('checking [%d/%d]: %s', files_parsed + 1, total_files, filename)

                ## TODO: Do we use MSFile here for local FS?
                ## What to do for other protocols?
                ## We need metadata at minimum (size, mtime)
                ##   and possible actual file data to compare hashes
                yield filename

                #existing_file = self.get_db_file(filename)
                #if existing_file:
                #    logger.info('file exists, skipping')
                #    files_skipped += 1
                #else:
                #    logger.info('file new, marking for addition')
                #    new_files.append(filename)
                #
                #files_parsed += 1
                #l_files_parsed += 1

        ## Exit without commit if no new files found
        #if not new_files:
        #    return list()

        ##logger.info('%d new files found, adding to database', len(new_files))
        #logger.info('%d new files found', len(new_files))
        #return new_files


class MSMirrorFTP(MSMirror):
    __tablename__ = 'mirror_ftp'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)
    #url = Column(String(256), nullable=False, unique=True)
    params = Column(sqlalchemy_jsonfield.JSONField(enforce_string=False))

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_ftp',
    }

    DEFAULT_PORT = 21

    def __init__(self, url, params=None):
        p_url = self.urlparse(url)
        if p_url['scheme'] != 'ftp':
            raise InvalidSchemeError

        self.url = url
        self.params = params
        self.f_size = {}
        self.f_mtime = {}

        #logger.info('connecting to %s', url)
        #self.connect()

    @orm.reconstructor
    def init_on_load(self):
        self.f_size = {}
        self.f_mtime = {}

    def connect(self):
        super(MSMirrorFTP, self).connect(self.url)
        try:
            #p_url = self.urlparse(url or self.url)
            p_url = self.urlparse(self.url)
            self.conn = ftplib.FTP()
            self.conn.connect(p_url['host'], p_url['port'])
            self.conn.login(p_url['user'], p_url['pass'])
            self.conn.cwd(p_url['path'])
            return True
        except:
            return False

    def listdir(self, path):
        dirlist = list()
        dirs = list()
        files = list()
        try:
            self.conn.cwd(path)
        except ftplib.error_perm:
            logger.error('unable to change directory to %s, currently in %s', path, self.conn.pwd())
            return dirs, files

        self.conn.retrlines('LIST', lambda x: dirlist.append(x.split()))
        for entry in dirlist:
            #logger.debug('entry : %s', entry)
            ls_info, size, mtime, fname = entry[0], entry[4], ' '.join(entry[5:8]), ' '.join(entry[8:])
            if ls_info.startswith('d'):
                dirs.append(fname)
            else:
                files.append(fname)
                self.f_size[os.path.join(path, fname)] = int(size)
                self.f_mtime[os.path.join(path, fname)] = dateparser.parse(mtime)
        return dirs, files

    def walk(self, path):
        path = os.path.join('/', path)
        dirs, files = self.listdir(path)
        #logger.debug('files : %s', files)
        yield path, dirs, files
        for d in dirs:
            #logger.debug('in path %s, parsing %s', path, d)
            _path = os.path.join(path, d)
            for f in self.walk(_path):
                yield f

    def get_size(self, fname):
        return self.f_size.get(fname, -1)

    def get_mtime(self, fname):
        return self.f_mtime.get(fname, -1)


class MSMirrorSFTP(MSMirror, json.JSONEncoder):
    __tablename__ = 'mirror_sftp'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)
    #url = Column(String(256), nullable=False, unique=True)
    params = Column(sqlalchemy_jsonfield.JSONField(enforce_string=False))

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_sftp',
    }

    DEFAULT_PORT = 22

    def __init__(self, url, params=None):
        p_url = self.urlparse(url)
        if p_url['scheme'] != 'sftp':
            raise InvalidSchemeError
        if not params.get('key'):
            raise MissingCredentialsError

        self.url = url
        self.params = params

    def connect(self):
        super(MSMirrorSFTP, self).connect(self.url)
        try:
            self.client = SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            self.client.connect('localhost', key_filename=self.params['key'])
            self.sftp = self.client.open_sftp()
            return True
        except:
            return False

    # https://gist.github.com/johnfink8/2190472
    def walk(self, path='.'):
        dirs = list()
        files = list()
        for f in self.sftp.listdir_attr(path):
            if S_ISDIR(f.st_mode):
                dirs.append(f.filename)
            else:
                files.append(f.filename)
        yield path, dirs, files
        for d in dirs:
            _path = os.path.join(path, d)
            for f in self.walk(_path):
                yield f


class MSMirrorFile(Base):
    __tablename__ = 'mirror_files'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    file = relationship('MSFile', backref='mirrors')
    mirror_id = Column(Integer, ForeignKey('mirror.id'))
    mirror = relationship('MSMirror', backref='files')
    #filename = Column(String(256), nullable=False, unique=True)

    def __init__(self, src_file, src_mirror):
        self.file = src_file
        self.mirror = src_mirror

    def __repr__(self):
        return '<MSMirrorFile id=%d, file=%s, mirror=%s>' % (self.id, self.file, self.mirror)


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
