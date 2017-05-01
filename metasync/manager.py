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
import sys
import os
import re

from file import MSFile
from mirror import build_mirror, MSMirror, MSMirrorFS, MSMirrorSFTP, MSMirrorFile
from main import Base, FileMissingError, NullHashError, DefaultEncoder


logger = logging.getLogger(__name__)


########################
### Execution object ###
########################

class MSExecution(Base):
    __tablename__ = 'execution'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    result = Column(String(64))

    def __init__(self, ts=datetime.now()):
        self.timestamp = ts


######################
### History object ###
######################

class MSHistory(Base, json.JSONEncoder):
    __tablename__ = 'history'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'))
    file = relationship('MSFile', backref='history')
    #filename = Column(Integer, ForeignKey("files.id"), nullable=False)
    status = Column(String(64), nullable=False)  # new, update
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

    # TODO: fix this ugly hack
    @orm.reconstructor
    def init_on_load(self):
        self.data = json.loads(self.data)

    def __repr__(self):
        return '<History {0} file={1} status={2} timestamp={3} execution={4} data={5}>'.format(
            self.id, self.file, self.status, self.timestamp, self.execution_id, self.data)


######################
### Manager object ###
######################

class MSManager(object):

    def __init__(self, db, params):
        logger.info('initializing database %s', db)
        engine = create_engine('sqlite:///%s' % db)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.sasession = Session()
        self.execution = MSExecution()
        self.params = params

        logger.info('reading files from database')
        self.existing_files = self.sasession.query(MSFile).all()
        self.ignored_files = list()  # TODO:load from file if new, otherwise db
        self.missing_files = list()

        # Reconcile the DB data with on-disk bits
        if len(self.existing_files) == 0:
            logger.info('database empty/new, skipping verification')
            return

        if not self.params.get('path'):
            return

        self.verify_files(self.params['path'])

    ### Verify internal list of known files ###
    def verify_files(self, path):
        logger.info('verifying database')

        if self.params.get('verify') == 'none':
            logger.info('invoked with verify=none, skipping verification')
            return
        elif self.params.get('verify') == 'all' or not path:
            verify_files = self.existing_files
        elif self.params.get('verify') == 'path':
            verify_files = filter(lambda x: os.path.samefile(path, x.file_path), self.existing_files)
        elif self.params.get('verify') == 'recurse':
            verify_files = filter(lambda x: path in x.file_path, self.existing_files)
        else:
            logger.error('invoked with invalid verify=%s, defaulting to all files', self.params.get('verify'))
            verify_files = self.existing_files

        logger.info('%d total files found, %d to be scanned', len(self.existing_files), len(verify_files))
        files_scanned = 0

        for msfile in verify_files:
            logger.debug('visiting [%d/%d] %s', files_scanned + 1, len(verify_files), msfile.filename)

            # Detect if any changes are made to file
            # If so, update in DB and add history entry
            try:
                modified = msfile.visit(self.params.get('strong_verify', False))
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

        if len(self.missing_files) == 0:
            logger.info('verification completed, all files accounted for')
        else:
            logger.info('verification completed, %d files missing', len(self.missing_files))

        return len(self.missing_files)

    ### Generate filename/path changes based upon previous timestamp ###
    def build_diff(self, start, end):
        logger.info('building diff between %s and %s', start, end)
        for msfile in self.existing_files:
            msfile.build_fn_diff(start)
            #hist_idx = filter(lambda x:start <= x[1].timestamp and x[1].timestamp <= end,
            #    enumerate(sorted(msfile.history, key=lambda x:x.timestamp)))

    #
    # Scan a path
    #
    # - Search for new files
    #
    def scan_new_files(self, path):
        logger.info('scanning path %s', path)
        files_parsed = files_skipped = total_files = 0
        new_files = list()
        #known_files = self.existing_files

        # Walk through filesystem
        # Iterate over files, checking if new or existing
        # Store in a temporary array
        for root, dirs, files in os.walk(path):
            logger.debug('descending into %s: %d files, %d directories found', root, len(files), len(dirs))
            total_files += len(files)
            l_files_parsed = 0

            for name in files:
                if files_parsed % 10 == 0 and files_parsed > 0:
                    logger.debug('status: %d skipped, %d new, %d parsed, %d total (%2.0f%% complete)',
                                 files_skipped, len(new_files), files_parsed, total_files, l_files_parsed / float(len(files)) * 100)

                filename = os.path.join(root, name)
                logger.info('checking [%d/%d]: %s', files_parsed + 1, total_files, filename)

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
            return list()

        #logger.info('%d new files found, adding to database', len(new_files))
        logger.info('%d new files found', len(new_files))
        return new_files

    # Iterate through newly detected files
    # First, compare against missing list (file was moved)
    # Then compare against existing known files (dedup detection, if enabled)
    def verify_add_new_files(self, new_files):
        for new_fn in new_files:
            if len(self.missing_files) > 0:
                new_missing_files = self.scan_dup_content_match(new_fn, self.missing_files)
                if new_missing_files:
                    (new_file, missing_file) = new_missing_files
                    logger.warning('updating missing file %s to match new %s', missing_file, new_file)
                    # NOTE: We update file, new data calculated here and history generated
                    if not self.params.get('dry', False):
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
            if self.params.get('dedup', False):
                new_dupe_files = self.scan_dup_content_match(new_fn, self.existing_files)
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
                if not self.params.get('dry', False):
                    self.add_file(new_fn, delay_commit=True)

        self.sasession.commit()

    ### Add a file to DB ###
    def add_file(self, filepath, delay_commit=False):
        #logger.debug('adding new file at %s', filepath)
        new_file = MSFile(filepath)
        self.sasession.add(new_file)
        self.sasession.flush()
        new_history = MSHistory(new_file, new_file.to_json(), self.execution, status='new')
        if not self.params.get('dry', False):
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
    def scan_dup_content_match(filename, source):
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

    #
    # Scan DB for matches on existing files (only metadata)
    #
    # This will be used by mirror logic to scan any new files
    # on a mirror to known existing files in the database
    #
    # Used when adding new mirrors, to match files that have
    # already been copied.  Only match on identical sizes by
    # default.  If same filename but different size, do not
    # count as match.
    #
    def scan_existing_meta_match(self, filename, size):
        match = filter(lambda x: x.filename == filename and x.size == size, self.existing_files)
        return match

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

    ### Mirror functions ###
    # Pull mirror from DB
    def get_mirror(self, host):
        mirror = self.sasession.query(MSMirror).filter(MSMirror.url == host).first()
        return mirror

    # Add a mirror to DB
    def add_mirror(self, location, params=None):
        logger.info('adding mirror %s', location)
        mirror = build_mirror(location, params)

        if mirror.connect():
            self.sasession.add(mirror)
            self.sasession.commit()
        else:
            logger.error('unable to connect to mirror, aborting add')

    # Walk through mirror and scan files
    # Look for matches to existing files
    # Test on filename, size.
    # TODO: Plan out if we want to verify hashes
    # (this would be expensive, involving download
    # of all data from mirror and storing in a
    # temporary location to compute data)
    def walk_scan_mirror(self, host, path):
        mirror = self.get_mirror(host)
        if not mirror.connect():
            logger.error('unable to connect, aborting')
            return

        for mpath, mdirs, mfiles in mirror.walk(path):
            for mfile in mfiles:
                mfile_path = os.path.join(mpath, mfile)
                size = mirror.get_size(mfile_path)
                mtime = mirror.get_mtime(mfile_path)
                logger.info('found mirror file %s, size %d, time %s', mfile_path, size, mtime)

                db_matches = self.scan_existing_meta_match(mfile_path, size)
                logger.info('match on existing files: %s', db_matches)


