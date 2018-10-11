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
import errno
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


class InvalidSchemeError(Exception):
    pass

class MissingCredentialsError(Exception):
    pass

class InvalidPathError(Exception):

    def __init__(self, filename):
        super(Exception, self).__init__(filename)
        self.filename = filename

    def __str__(self):
         return "Path {0} not found".format(self.filename)


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


class MSMirror(Base, json.JSONEncoder):
    __tablename__ = 'mirror'

    id = Column(Integer, primary_key=True)
    type = Column(String(64), nullable=False)
    hostname = Column(String(256))
    path = Column(String(256))
    last_check = Column(DateTime)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror',
        'polymorphic_on': type
    }

    def __init__(self, url, params=None):
        self.last_check = datetime.now()

    def __repr__(self):
        return '<MSMirror %s:%s type=%s>' % (self.hostname, self.path, self.type)

    def urlparse(self, url):
        p_url = dict()
        res = urlparse.urlparse(url)
        p_url['scheme'] = res.scheme
        p_url['host'] = res.hostname
        p_url['path'] = res.path or '/'

        # Assume that any subclass with port defined is tcp-based
        # and may have connection port or credentials, provide defaults
        if hasattr(self, 'DEFAULT_PORT'):
            p_url['port'] = res.port or self.DEFAULT_PORT
            p_url['user'] = res.username or self.DEFAULT_USER
            p_url['pass'] = res.password or ''

        #logger.debug('parsed URL: {scheme}://{host}:{port}{path}, user={user}, pass={pass}'.format(**p_url))
        #logger.debug('parsed URL: %s', urlparse.urlunparse(res))
        return p_url

    @staticmethod
    def connect(url):
        logger.debug('connecting to %s', url)

    def test_walk(self, path):
        for mpath, mdirs, mfiles in self.walk(path):
            for mfile in mfiles:
                logger.info('found mirror file %s', mfile)

    def sync(self, src, dest):
        raise NotImplementedError


class MSMirrorFS(MSMirror):
    __tablename__ = 'mirror_fs'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_fs',
    }

    # For MirrorFS, we take in "file://" url to init
    # but otherwise url is not used (assumed localhost)
    def __init__(self, url, params=None):
        super(MSMirrorFS, self).__init__(url, params)
        p_url = self.urlparse(url)
        if p_url['scheme'] != 'file':
            raise InvalidSchemeError
        if p_url['host'] != None and p_url['host'] != 'localhost':
            raise InvalidSchemeError

        self.params = params
        self.hostname = 'localhost'
        self.path = os.path.normpath(p_url['path'])
        self.connect(self.path)

    def connect(self):
        super(MSMirrorFS, self).connect(self.path)
        if not os.path.isdir(self.path):
            raise InvalidPathError(self.path)
        return True

    def walk(self):
        logger.info('scanning path %s', self.path)
        for root, dirs, files in os.walk(self.path):
            logger.debug('descending into %s: %d files, %d directories found', root, len(files), len(dirs))
            yield root, dirs, files


class MSMirrorTCP(MSMirror):

    url = Column(String(256), nullable=False, unique=True)
    #hostname = Column(String(256))
    port = Column(Integer)
    username = Column(String(256))
    password = Column(String(256))
    params = Column(sqlalchemy_jsonfield.JSONField(enforce_string=False))

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_tcp',
    }

    def __init__(self, url, params=None):
        super(MSMirrorTCP, self).__init__(url, params)
        p_url = self.urlparse(url)
        self.url = url
        self.params = params
        self.path = p_url['path']
        self.hostname = p_url['host']
        self.port = p_url['port']
        self.username = p_url['user']
        self.password = p_url['pass']


class MSMirrorFTP(MSMirrorTCP):
    __tablename__ = 'mirror_ftp'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_ftp',
    }

    DEFAULT_PORT = 21
    DEFAULT_USER = 'anonymous'

    def __init__(self, url, params=None):
        super(MSMirrorFTP, self).__init__(url, params)
        p_url = self.urlparse(url)
        if p_url['scheme'] != 'ftp':
            raise InvalidSchemeError

        # We cache filesize + mtime
        # from directory listings with FTP
        self.init_on_load()

        #self.connect()

    @orm.reconstructor
    def init_on_load(self):
        self.f_size = {}
        self.f_mtime = {}

    def connect(self):
        super(MSMirrorFTP, self).connect(self.url)
        try:
            self.conn = ftplib.FTP()
            self.conn.connect(self.hostname, self.port)
            self.conn.login(self.username, self.password)
            self.conn.cwd(self.path)
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

        # Iterate through files in dir, add new dirs to list to iterate
        # Add files to file list, cache size + mtime
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

    def walk(self):
        path = os.path.join('/', self.path)
        dirs, files = self.listdir(path)
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

    def exists(self, path):
        f_name = os.path.basename(path)
        f_path = os.path.dirname(path)
        (dirs, files) = listdir(f_path)
        if f_name in files:
            return True
        return False

    # Rename src to dest
    def mv(self, src, dest):
        # TODO: We need to implement an exists() here
        # using os.path.split and listdir
        logger.debug('moving %s to %s', src, dest)
        self.conn.rename(os.path.join(self.path, src), os.path.join(self.path, dest))


class MSMirrorSFTP(MSMirrorTCP, json.JSONEncoder):
    __tablename__ = 'mirror_sftp'

    id = Column(Integer, ForeignKey('mirror.id'), primary_key=True)

    __mapper_args__ = {
        'polymorphic_identity': 'mirror_sftp',
    }

    DEFAULT_PORT = 22
    DEFAULT_USER = os.environ['USER']

    def __init__(self, url, params=None):
        super(MSMirrorSFTP, self).__init__(url, params)
        p_url = self.urlparse(url)
        if p_url['scheme'] != 'sftp':
            raise InvalidSchemeError
        if not params.get('key') or not os.path.isfile(params['key']):
            raise MissingCredentialsError

    def connect(self):
        super(MSMirrorSFTP, self).connect(self.url)
        try:
            self.client = SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            logger.debug('connecting to %s with key %s', self.hostname, self.params['key'])
            self.client.connect(self.hostname, key_filename=self.params['key'])
            self.conn = self.client.open_sftp()
            #logger.debug('changing directory to %s', self.path)
            #self.conn.chdir(self.path)
            return True
        except:
            return False

    # https://gist.github.com/johnfink8/2190472
    def walk(self):
        #logger.debug('self path=%s, called path=%s', self.path, path)
        #npath = abspath_re.sub('', path)
        dirs = list()
        files = list()
        #npath = self.path_join(self.path)
        npath = self.path
        logger.debug('walking path %s', npath)
        for f in self.conn.listdir_attr(npath):
            if S_ISDIR(f.st_mode):
                dirs.append(f.filename)
            else:
                files.append(f.filename)
        yield self.path, dirs, files
        for d in dirs:
            _path = os.path.join(path, d)
            for f in self.walk(_path):
                yield f

    # Custom os.path.join to remove any slash prefix
    def path_join(self, path):
        abspath_re = re.compile(r'^/+')
        return os.path.join(self.path, abspath_re.sub('', path))

    def get_size(self, fname):
        logger.debug('checking size on %s', fname)
        #return self.conn.lstat(self.path_join(fname)).st_size
        return self.conn.lstat(fname).st_size

    def get_mtime(self, fname):
        #return self.conn.lstat(self.path_join(fname)).st_mtime
        return datetime.fromtimestamp(self.conn.lstat(fname).st_mtime)

    # Custom FTPlib implementation of os.path.exists
    def exists(self, path):
        try:
            self.conn.stat(path)
        except IOError, e:
            if e.errno == errno.ENOENT:
                return False
            raise
        else:
            return True

    # Rename src to dest
    def mv(self, src, dest):
        if self.exists(dest):
            logger.error('unable to rename %s to %s, destination already exists', src, dest)
            return False
        logger.debug('moving %s to %s', src, dest)
        self.conn.rename(os.path.join(self.path, src), os.path.join(self.path, dest))


class MSMirrorFile(Base):
    __tablename__ = 'mirror_files'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    file = relationship('MSFile', backref='mirrors')
    mirror_id = Column(Integer, ForeignKey('mirror.id'))
    mirror = relationship('MSMirror', backref='files')
    last_visit = Column(DateTime)

    def __init__(self, src_file, src_mirror, ts=None):
        self.file = src_file
        self.mirror = src_mirror
        self.last_visit = datetime.now() if ts is None else ts

    def __repr__(self):
        return '<MSMirrorFile id=%d, file=%s, mirror=%s last_visit=%s>' % \
                    (self.id, self.file, self.mirror, self.last_visit)


#
# mirror_sftp
# id=1 host=sftp://user:pass@my.pictures.com/ path=/backup
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
