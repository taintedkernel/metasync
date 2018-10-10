from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, orm

import click
#import click_log

try:
    import simplejson as json
except ImportError:
    import json

from datetime import datetime, timedelta
import time

import tempfile
import urlparse
import shutil

import logging
import sys
import os
import re

from repo import MSRepo
from file import MSFile
from mirror import build_mirror, MSMirror, MSMirrorFS, MSMirrorSFTP, MSMirrorFile
from main import Base, FileMissingError, NullHashError, DefaultEncoder


# Max timestamp difference to determine
# file has been modified on remote system
# May need to be adjusted and clocks must be in sync!
MAX_TS_DELTA = 60


logger = logging.getLogger(__name__)


class NoRepoError(Exception):
    pass


########################
### Execution object ###
########################

class MSExecution(Base):
    __tablename__ = 'execution'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    result = Column(String(64))

    def __init__(self, ts=None):
        self.timestamp = datetime.now() if ts is None else ts


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

    def __init__(self, hfile, data, execution, status='update', ts=None):
        self.file = hfile
        self.status = status
        self.data = data
        self.timestamp = datetime.now() if ts is None else ts
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

    def __init__(self, db, repo_path, params):
        logger.info('initializing database %s', db)

        engine = create_engine('sqlite:///%s' % db)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.sasession = Session()

        self.params = params
        self.execution = MSExecution()

        # Get repo from the DB
        #
        # If not present and create_missing flag
        # passed, create & commit new repo, then
        # continue.  If not present and no_repo
        # flag passed, acknowledge and continue.
        repo = self.get_repo(repo_path)
        if not repo:
            if params.get('create_missing_repo', False):
                repo =  MSRepo(repo_path)
                self.sasession.add(repo)
                self.sasession.commit()
            elif params.get('mgr_no_repo', False):
                # Used in functionality where we do not
                # need to interact with any repo data.
                #
                # We do not check presence of a correct
                # repo in functions, they will fail
                # when executed at some point.
                logger.info('manager invoked without repo, continuing without initialization')
                return
            else:
                raise NoRepoError
        self.repo = repo

        logger.info('reading files from database')
        self.existing_files = self.sasession.query(MSFile).all()
        self.ignored_files = list()  # TODO:load from file if new, otherwise db
        self.missing_files = list()

        # Reconcile the DB data with on-disk bits
        if len(self.existing_files) == 0:
            logger.info('database empty/new, skipping verification')
        else:
            self.verify_files()

    ### Get a repo ###
    def get_repo(self, repo_path):
        try:
            repo = self.sasession.query(MSRepo).filter(MSRepo.path == repo_path).one()
        except orm.exc.NoResultFound:
            repo = None
        return repo

    ### Verify internal list of known files ###
    def verify_files(self):
        path = self.repo.path
        logger.info('starting database verification')

        if self.params.get('verify') == 'none':
            logger.info('invoked with verify=none, skipping verification')
            return
        elif self.params.get('verify') == 'all' or not path:
            verify_files = self.existing_files
        #elif self.params.get('verify') == 'path':
        #    verify_files = filter(lambda x: os.path.samefile(path, x.file_path), self.existing_files)
        #elif self.params.get('verify') == 'recurse':
        #    verify_files = filter(lambda x: path in x.file_path, self.existing_files)
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

        ### UNIT TEST ###
        if len(self.missing_files) == 0:
            logger.info('verification completed, all files accounted for')
        else:
            logger.info('verification completed, %d files missing', len(self.missing_files))
        ### END ###

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
    def scan_new_files(self, path=None):
        if not path:
            path = self.repo.path
        logger.info('starting new file scan on %s', path)
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

                filename = os.path.relpath(os.path.join(root, name), self.repo.path)
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

        #logger.info('%d new files found, adding to database', len(new_files))
        logger.info('scanning complete, %d new files found', len(new_files))
        return new_files

    # Iterate through newly detected files
    # First, compare against missing list (file was moved)
    # Then compare against existing known files (dedup detection, if enabled)
    def verify_add_new_files(self, new_files):
        logger.info('starting verify/add new files')
        for new_fn in new_files:

            # Check against missing files
            # TODO: same logic as dupes, combine them: one missing, one existing
            if len(self.missing_files) > 0:
                new_missing_files = self.scan_dup_content_match(new_fn, self.missing_files)
                if new_missing_files:
                    (new_file, missing_file) = new_missing_files
                    #### UNIT TEST ###
                    logger.warning('updating missing file %s to match new %s', missing_file, new_file)
                    ### END ###

                    # NOTE: We update file, new data calculated here and history generated
                    if not self.params.get('dry', False):
                        keys = ['filename', 'mtime', 'ctime', 'last_visit', 'status']
                        values = [new_fn, new_file.mtime, new_file.ctime, datetime.now(), 'valid']
                        data = dict(zip(keys, values))
                        new_history = self.update_file_helper(missing_file, data)
                        #new_history = missing_file.update(data)
                        self.sasession.add(missing_file)
                        self.sasession.add(new_history)
                        self.sasession.commit()
                        missing_file.show_history()
                    continue

            # Next, compare against existing known file data (file was copied/linked)
            # TODO: any reason we wouldn't want to do this always (asides from cost)?
            if self.params.get('dedup', False):
                new_dupe_files = self.scan_dup_content_match(new_fn, self.existing_files)
                if new_dupe_files:
                    (new_file, dupe_file) = new_dupe_files
                    ### UNIT TEST ###
                    logger.warning('duplicate file detected:')
                    logger.warning('  new file:      %s', new_file)
                    logger.warning('  existing file: %s', dupe_file)
                    ### END ###
                    logger.warning('leaving to manual intervention')
                    # TODO : add functionality for automatic handling
                    #   and create necessary history entries
                    continue

            # If no other match, then assume new
            if self.check_file_eligable(new_fn):
                if not self.params.get('dry', False):
                    self.add_file(new_fn, delay_commit=True)

        self.sasession.commit()
        logger.info('verify/add new files complete')

    ### Add a new repo to DB ###
    def add_repo(self, path):
        logger.debug('creating new repo at %s', path)
        repo = self.get_repo(path)
        if repo:
            logger.error('repo already exists, aborting: %s', repo)
            return
        if not os.path.isdir(path):
            logger.error('path %s is not directory, aborting')
            return

        repo = MSRepo(path)
        self.sasession.add(repo)
        return repo

    ### Add a file to DB ###
    def add_file(self, filepath, delay_commit=False):
        logger.debug('adding new file at %s', filepath)
        new_file = MSFile(filepath, self.repo)
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
    def get_db_file(self, filename):
        # TODO: Do we scan DB directly instead of self.existing_files?
        #filtered_files = sorted(filter(lambda x: x.filename == file_path, self.existing_files), key=lambda y: y.added_time)
        filtered_files = filter(lambda x: x.filename == filename, self.existing_files)
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
    def scan_dup_content_match(self, filename, source):
        new_file = MSFile(filename, self.repo)
        match = filter(lambda x: x.size == new_file.size and x.sha256 == new_file.sha256 and x.filename != new_file.filename and new_file.repo == self.repo, source)
        if len(match) == 0:
            return None
        elif len(match) == 1:
            matched_file = match.pop()
            ### UNIT TEST ###
            logger.info('match on %s found with %s', matched_file, filename)
            ### END ###
            return (new_file, matched_file)
        else:
            logger.error('multiple files returned on match for %s, aborting', filename)
            logger.error('matches:')
            for f in match:
                logger.error('  %s', f)
            return None

    #
    # Scan DB for metadata matches on existing files
    #
    # This will be used by mirror logic to scan any new files
    # on a mirror to known existing files in the database
    #
    # Used when adding new mirrors, to match files that have
    # already been copied.  Only match on identical sizes by
    # default.  If same filename but different size, do not
    # count as match.
    #
    # TODO: Make this static method as above?  At least unify approaches
    #
    def scan_existing_meta_match(self, filename, size):
        filename = os.path.basename(filename)
        if len(self.existing_files) < 10:
            logger.debug('checking for file %s (size %s) against %s', filename, size, self.existing_files)
        else:
            logger.debug('checking for file %s (size %s) against existing files', filename, size)
        match = filter(lambda x: os.path.basename(x.filename) == filename and x.size == size, self.existing_files)
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
    def get_mirror(self, url):
        # logger.debug('retriving mirror on %s', url)
        res = urlparse.urlparse(url)
        host = res.hostname
        path = res.path or '/'
        # logger.debug('%s', self.sasession.query(MSMirror).all())
        mirror = self.sasession.query(MSMirror).filter(MSMirror.hostname == host).filter(MSMirror.path == path).one()
        return mirror

    # Add a mirror to DB
    def add_mirror(self, location, params=None):
        logger.info('adding mirror %s', location)
        mirror = build_mirror(location, params)

        logger.debug('testing mirror %s', location)
        if mirror.connect():
            self.sasession.add(mirror)
            self.sasession.commit()
        else:
            logger.error('unable to connect to mirror, aborting add')

    #
    # Verify files on our mirror
    #
    # Opposite approach of walk_scan_mirror, here
    # we iterate through our local files and check against
    # what's on the mirror
    #
    # TODO: Thinking we either run verify_files (to validate
    # "local" data first) and then compare each to mirror_file?
    # Do we combine functionality in one method?
    # Do we skip local files?
    def verify_update_host_files(self, url):
        logger.debug('verifying files on host %s', url)
        mirror = self.get_mirror(url)
        if not mirror:
            logger.error('unable to find mirror %s', url)
            return
        if not mirror.connect():
            logger.error('unable to connect, aborting')
            return

        logger.info('verifying files on mirror %s, last check on %s', mirror, mirror.last_check)
        missing_files = []
        for mf in mirror.files:

            # Determine current metadata at time of last mirror check
            sync_metadata = mf.file.get_history_ts(mirror.last_check)
            logger.debug('returned metadata: %s', sync_metadata)

            # Metadata return only contains fields that were changed,
            # meaning the data we're looking for may not be present
            # in which case take it from the main file table
            try:
                sync_fn = sync_metadata['filename']
            except KeyError:
                sync_fn = mf.file.filename
            try:
                sync_size = sync_metadata['size']
            except KeyError:
                sync_size = mf.file.size
            sync_mtime = datetime.strptime(sync_metadata['mtime'], '%Y-%m-%d %H:%M:%S')
            sync_path = os.path.join(mirror.path, sync_fn)
            logger.info('file %s mirrored to %s at time %s', mf.file, sync_path, mirror.last_check)

            # We also get latest metadata from mirror, to ensure file
            # has not been modified on remote host
            try:
                mirror_size = mirror.get_size(sync_path)
                mirror_mtime = mirror.get_mtime(sync_path)
            except IOError:
                logger.warning('file %s not present, skipping', sync_path)
                missing_files.append(sync_path)
                continue
            logger.info('found size %d, mtime %s on file %s', mirror_size, mirror_mtime, mf.file)

            ### Sync logic ###
            logger.debug('local/current file: fn=%s  size=%d  mtime=%s', mf.file.filename, mf.file.size, mf.file.mtime)
            logger.debug('sync/history file:  fn=%s  size=%d  mtime=%s', sync_fn, sync_size, sync_mtime)
            logger.debug('mirror file:        size=%d  mtime=%s', mirror_size, mirror_mtime)

            # First we should check if mirror file has been modified
            # since our last sync, this would be split-brain and we
            # should warn user and prevent further action without
            # confirmation. This indicates the mirror file has been
            # modified without our knowledge and taking no automation
            # action is safest course. However, since we intend to keep
            # local data as source-of-truth we should have option to
            # overwrite remote file data if user confirms.
            if sync_size != mirror_size or abs(sync_mtime - mirror_mtime) > timedelta(MAX_TS_DELTA):
                logger.error('remote file %s has been modified!', sync_fn)
                continue

            # Check if our local file has been renamed/moved
            if sync_fn != mf.file.filename and mirror_size == mf.file.size:
                # Try to perform a mv/rename here if possible,
                # significantly more efficient and reduces off-chance of corruption
                ### UNIT TEST ###
                logger.info('renaming mirror %s to match local %s', sync_fn, mf.file.filename)
                ### END ###

                # TODO: We need to ensure that mf.filename does not exist on remote server already
                # Rename API's used for Paramiko and ftplib *should* prevent overwrites, but not tested
                # Rename <existing/old> to <new/local>
                mirror.mv(sync_fn, mf.file.filename)

            # Check if our local file has been updated
            elif sync_fn == mf.file.filename and mirror_size != mf.file.size:
                logger.info('syncing local %s to mirror %s', mf.file.filename, sync_fn)
                # Copy <new/local> to <existing/remote>
                mirror.sync(mf.file.filename, sync_fn)

            else:
                ### UNIT TEST ###
                logger.debug('mirror up to date with local %s', mf.file)
                ### END ###

        for mf in missing_files:
            logger.info('file %s missing', mf)

        mirror.last_check = datetime.now()
        self.sasession.add(mirror)
        self.sasession.commit()

    # Wrapper to call walk_scan_mirror with a host
    def walk_scan_host(self, url):
        mirror = self.get_mirror(url)
        if not mirror:
            logger.error('unable to find mirror %s', url)
            return
        self.walk_scan_mirror(mirror)

    #
    # Walk through mirror and scan files
    # Look for matches to existing files
    # Test on filename, size.
    # If match, create association and store to DB
    #
    # To be used to add new mirror already populated
    # with data and match against existing local data
    # Mainly used for unittests, likely not needed
    # by end user (since we intend to create new mirrors
    # and sync data internally with application)
    # This may be helpful if a user has an existing backup
    # with recent data and wants to "import" this as a
    # mirror into metasync
    #
    # TODO: Plan out if we want to verify hashes
    # (this would be expensive, involving download
    # of all data from mirror and storing in a
    # temporary location to compute data)
    def walk_scan_mirror(self, mirror):
        logger.debug('scanning mirror %s', mirror)
        if not mirror.connect():
            logger.error('unable to connect, aborting')
            return

        for mpath, mdirs, mfiles in mirror.walk():
            for mfile in mfiles:
                mfile_path = os.path.join(mpath, mfile)
                size = mirror.get_size(mfile_path)
                mtime = mirror.get_mtime(mfile_path)
                logger.info('found mirror file %s, size %d, time %s', mfile_path, size, mtime)

                db_matches = self.scan_existing_meta_match(mfile_path, size)
                logger.info('match on existing files: %s', db_matches)

                if len(db_matches) == 1:
                    mf = MSMirrorFile(db_matches[0], mirror)
                    self.sasession.add(mf)
                    self.sasession.commit()
                    logger.info('created mirror file %s', mf)
                elif len(db_matches) > 1:
                    logger.debug('multiple matches found, skipping')
                elif len(db_matches) == 0:
                    logger.debug('no matches found')

        mirror.last_visit = datetime.now()
        self.sasession.add(mirror)
