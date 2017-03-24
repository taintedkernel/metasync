from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

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


Base = declarative_base()
logger = logging.getLogger('metasync')

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


#######################
##### File object #####
#######################

class MSFile(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    filename = Column(String(256), nullable=False, unique=True)
    status = Column(String(64), default='valid')
    size = Column(Integer, default=0)
    mtime = Column(DateTime)
    ctime = Column(DateTime)
    sha256 = Column(String(64), default=None)
    #added_time = Column(DateTime)
    last_visit = Column(DateTime)
    #history

    # TODO: Do we really need functionality to specify a custom sha256?
    # Maybe in cases where we are trying to recover from corruption?
    # Also, might want to support a "lite" mode where files are not hashed
    # FYI Sqlalchemy utilizes __new__ (not __init__)
    def __init__(self, filename, sha256=None, verify_exist=True, compute_hash=True):
        if verify_exist:
            if not os.path.exists(filename):
                raise InvalidFileError

        self.filename = filename

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
        #self.added_time = now

    def __repr__(self):
        #return '<{0} mtime={1} size={2} sha256={3} last_visit={4} added={5}>'\
        #        .format(self.filename, self.mtime, self.size, self.sha256[:16],\
        #                self.last_visit, self.added_time)
        return '<File {0} name={1} mtime={2} size={3} sha256={4} last_visit={5}>'.format(self.id, self.filename, self.mtime.strftime('%Y-%m-%d %H:%M:%S'), self.size, self.sha256[:16], self.last_visit.strftime('%Y-%m-%d %H:%M:%S'))

    def to_json(self):
        serial = dict()
        serial['filename'] = self.filename
        serial['sha256'] = self.sha256
        serial['size'] = self.size
        serial['mtime'] = self.mtime.strftime('%Y-%m-%d %H:%M:%S')
        serial['ctime'] = self.ctime.strftime('%Y-%m-%d %H:%M:%S')
        #serial['added_time'] = self.added_time.strftime('%Y-%m-%d %H:%M:%S')
        serial['last_visit'] = self.last_visit.strftime('%Y-%m-%d %H:%M:%S')
        return json.dumps(serial)

    @property
    def file_name(self):
        return os.path.basename(self.filename)

    @property
    def file_path(self):
        return os.path.dirname(self.filename)

    def get_size(self):
        return os.path.getsize(self.filename)

    def get_mtime(self):
        return datetime.fromtimestamp(os.path.getmtime(self.filename))

    # We won't typically use this, but tracking regardless # # #
    def get_ctime(self):
        return datetime.fromtimestamp(os.path.getctime(self.filename))

    # Compute our file hash
    def compute_sha256(self, blocksize=65536):
        hasher = hashlib.sha256()
        with open(self.filename, 'rb') as f:
            buf = f.read(blocksize)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(blocksize)
            return hasher.hexdigest()

    def show_history(self):
        for h in self.history:
            logger.debug('%s', h)

    #
    # Visit the file
    #
    # This is verification the file still exists at the
    # same location, with the same contents.  Metadata
    # changes are not considered a change.
    #
    # Return True if contents modified, False otherwise
    #
    def visit(self, strong_verify=False):
        if not os.path.exists(self.filename):
            logger.warning('%s missing', self.filename)
            raise FileMissingError

        modified = dict()
        #ctime = self.get_ctime()
        #if ctime > self.last_visit:
        #    modified = True

        mtime = self.get_mtime()
        if mtime > self.last_visit:
            modified['mtime'] = mtime
            logger.info('%s mtime modified', self.filename)

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
        # NOTE: We may want to move modifications to Manager class,
        #   update_file_helper can be utilized
        #
        if len(modified) > 0 or strong_verify:
            sha256 = self.compute_sha256()
            if sha256 != self.sha256:
                logger.info('%s contents updated to %s', self.filename, sha256)

                if not any(modified.values()):
                    logger.fatal('possible data corruption on %s, contents changed without metadata change!', self.filename)
                    logger.error('manual investigation required, not updating database')
                    return None

                self.sha256 = sha256
                modified['sha256'] = sha256
                return modified
                #return True
            else:
                logger.info('%s detected as updated but contents unchanged, updating metadata', self)
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


############################
##### Execution object #####
############################

class MSExecution(Base):
    __tablename__ = 'execution'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    result = Column(String(64))

    def __init__(self, ts=datetime.now()):
        self.timestamp = ts


##########################
##### History object #####
##########################

class MSHistory(Base, json.JSONEncoder):
    __tablename__ = 'history'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    file = relationship('MSFile', backref='history')
    #filename = Column(Integer, ForeignKey("files.id"), nullable=False)
    status = Column(String(64), nullable=False)
    data = Column(String(1024), nullable=False)
    timestamp = Column(DateTime, nullable=False)
    execution_id = Column(Integer, ForeignKey('execution.id'))
    execution = relationship('MSExecution', backref='history')

    def __init__(self, hfile, data, execution, status='update', ts=datetime.now()):
        self.file = hfile
        self.status = status
        self.data = data
        self.timestamp = ts
        self.execution = execution

    def __repr__(self):
        return '<History {0} file={1} status={2} timestamp={3} execution={4} data={5}>'.format(self.id, self.file, self.status, self.timestamp, self.execution_id, self.data)


##########################
##### Manager object #####
##########################

class MSManager(object):

    def __init__(self, db, options):
        logger.info('initializing database %s', db)
        engine = create_engine('sqlite:///%s' % db)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.sasession = Session()
        self.execution = MSExecution()
        self.options = options

        logger.info('reading files from database')
        self.existing_files = self.sasession.query(MSFile).all()
        self.ignored_files = list()  # TODO:load from file if new, otherwise db
        self.missing_files = list()

        # Reconcile the DB data with on-disk bits
        if len(self.existing_files) > 0:
            self.verify_files()
        else:
            logger.info('database empty/new, skipping verification')


    ### Verify internal list of known files ###
    def verify_files(self):
        logger.info('verifying database')
        # TODO: handle option where we don't assume recursion
        verify_files = filter(lambda x: self.options['path'] in x.file_path or self.options['verify_all'], self.existing_files)
        logger.info('%d total files found, %d to be scanned', len(self.existing_files), len(verify_files))
        files_scanned = 0

        for msfile in verify_files:
            logger.debug('visiting [%d/%d] %s', files_scanned+1, len(verify_files), msfile.filename)

            # Detect if any changes are made to file
            # If so, update in DB and add history entry
            try:
                modified = msfile.visit(self.options.get('strong_verify', False))
            # Mark files as missing but do not commit to DB yet
            except FileMissingError:
                modified = False
                msfile.status = 'missing'
                self.missing_files.append(msfile)

            if modified:
                new_history = MSHistory(msfile, json.dumps(modified, cls=DefaultEncoder), self.execution)
                self.sasession.add(new_history)

            msfile.show_history()
            self.sasession.add(msfile)
            files_scanned += 1

        # Commit last_update and other updates
        self.sasession.commit()

        # TODO: do something with missing_files
        if len(self.missing_files) == 0:
            logger.info('verification completed, all files accounted for')
        else:
            logger.info('verification completed, %d files missing', len(self.missing_files))

        return len(self.missing_files)


    #
    # Scan a path
    #
    # - Search for new files
    # - Verify existing files
    #
    def scan_path(self):
        logger.info('scanning path %s', self.options['path'])
        files_parsed = files_skipped = total_files = 0
        new_files = list()
        known_files = self.existing_files

        for root, dirs, files in os.walk(self.options['path']):
            logger.debug('descending into %s: %d files, %d directories found', root, len(files), len(dirs))
            total_files += len(files)
            l_files_parsed = 0

            for name in files:
                if files_parsed % 10 == 0 and files_parsed > 0:
                    logger.debug('status: %d skipped, %d new, %d parsed, %d total (%2.0f%% complete)', files_skipped, len(new_files), files_parsed, total_files, l_files_parsed/float(len(files))*100)

                filename = os.path.join(root, name)
                logger.info('checking [%d/%d]: %s', files_parsed+1, total_files, filename)

                existing_file = self.get_db_file(filename)
                if existing_file:
                    logger.info('file exists, skipping')
                    files_skipped += 1
                else:
                    logger.info('file new, marking for addition')
                    new_files.append(filename)

                files_parsed += 1
                l_files_parsed += 1

        # Exit without commit if no new files found
        if not new_files:
            return 0

        logger.info('%d new files found, adding to database', len(new_files))

        # Iterate through newly detected files
        for new_fn in new_files:
            # First, compare against missing list (file was moved)
            if len(self.missing_files) > 0:
                new_missing_files = self.scan_content_match(new_fn, self.missing_files)
                if new_missing_files:
                    (new_file, missing_file) = new_missing_files
                    logger.warning('updating missing file %s to match new %s', missing_file, new_file)

                    # NOTE: We update file, new data calculated here and history generated
                    if not self.options.get('dry', False):
                        keys = ['filename', 'mtime', 'ctime', 'last_visit', 'status']
                        values = [new_fn, new_file.mtime, new_file.ctime, datetime.now(), 'valid']
                        data = dict(zip(keys, values))
                        new_history = self.update_file_helper(missing_file, data)
                        #new_history = missing_file.update(data)
                        self.sasession.add(missing_file)
                        self.sasession.add(new_history)
                        #self.sasession.commit()
                        missing_file.show_history()

                    continue

            # Next, compare against existing known file data (file was copied/linked)
            # TODO: any reason we wouldn't want to do this always (asides from cost)?
            if self.options.get('dedup', False):
                new_dupe_files = self.scan_content_match(new_fn, self.existing_files)
                if new_dupe_files:
                    (new_file, dupe_file) = new_dupe_files
                    logger.warning('duplicate file detected:')
                    logger.warning('  new file:      %s', new_file)
                    logger.warning('  existing file: %s', dupe_file)
                    logger.warning('leaving to manual intervention')
                    # TODO : add functionality for automatic handling
                    #   and create necessary history entries
                    continue

            # If no other match, then assume new
            if self.check_file_eligable(new_fn):
                if not self.options.get('dry', False):
                    self.add_file(new_fn, delay_commit=True)

        self.sasession.commit()


    ### Add a file to DB ###
    def add_file(self, filepath, delay_commit=False):
        #logger.debug('adding new file at %s', filepath)
        new_file = MSFile(filepath)
        self.sasession.add(new_file)
        self.sasession.flush()
        new_history = MSHistory(new_file, new_file.to_json(), self.execution, status='new')
        if not self.options.get('dry', False):
            self.sasession.add(new_history)
        logger.info('added %s', new_file)
        if not delay_commit:
            self.sasession.commit()
        self.existing_files.append(new_file)


    ### Check to see if file exists in DB ###
    def get_db_file(self, file_path):
        # TODO: Do we scan DB directly instead of self.existing_files?
        #filtered_files = sorted(filter(lambda x: x.filename == file_path, self.existing_files), key=lambda y: y.added_time)
        filtered_files = filter(lambda x: x.filename == file_path, self.existing_files)
        if len(filtered_files) == 0:
            return None
        elif len(filtered_files) == 1:
            pass
        else:
            logger.error('multiple files returned on match for %s, returning most recent:', file_path)
            for f in filtered_files:
                logger.error('  %s', f)
        return filtered_files.pop()


    ### Update a file and generate history object ###
    def update_file_helper(self, msfile, data):
        msfile.update(data)
        new_history = MSHistory(msfile, json.dumps(data, cls=DefaultEncoder), self.execution)
        return new_history


    #
    # Scan DB for any potential matches
    #
    # This will search for a match on "filename" with "source"
    #
    # Our logic currently will first look for matches on missing files
    # Then, if no match and dedup is enabled we can search further
    #   Both on existing, plus other new files
    #
    @staticmethod
    def scan_content_match(filename, source):
        new_file = MSFile(filename)
        match = filter(lambda x: x.size == new_file.size and x.sha256 == new_file.sha256 and x.filename != new_file.filename, source)
        if len(match) == 0:
            return None
        elif len(match) == 1:
            matched_file = match.pop()
            logger.info('match on %s found with %s', matched_file, filename)
            return (new_file, matched_file)
        else:
            logger.error('multiple files returned on match for %s, aborting', filename)
            logger.error('matches:')
            for f in match:
                logger.error('  %s', f)
            return None


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
