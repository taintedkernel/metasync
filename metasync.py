#!/usr/bin/env python

from sqlalchemy import Column, ForeignKey, Integer, String, UnicodeText, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from datetime import datetime
import time

import logging
import hashlib
import sys
import os
import re


Base = declarative_base()
logger = logging.getLogger(__name__)

class FileMissingError(Exception):
    pass

class InvalidFileError(Exception):
    pass

class NullHashError(Exception):
    pass


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
    added_time = Column(DateTime)
    last_visit = Column(DateTime)

    # TODO: Do we really need functionality to specify a custom sha256?
    # Maybe in cases where we are trying to recover from corruption?!?...
    # The more I think, the less useful this seems (for now at least)
    # Sqlalchemy utilizes __new__ (not __init__)
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
    #   mtime, size (+assume hash) modified - file saved, update by default
    #   mtime modified - file saved with same data, update by default
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
            logger.warning('%s missing', self.filename)
            raise FileMissingError

        modified = dict()
        #ctime = self.get_ctime()
        #if ctime > self.last_visit:
        #    modified = True

        mtime = self.get_mtime()
        if mtime > self.last_visit:
            modified['mtime'] = True
            logger.info('%s mtime modified', self.filename)

        size = self.get_size()
        if size != self.size:
            modified['size'] = True
            logger.info('%s size modified', self.filename)

        #
        # If file timestamps modified or we want
        # a byte-level verification, then recompute hash
        #
        # TODO: Need logic to determine if completely new file.
        #   May need to prompt user.
        #
        if any(modified.values()) or strong_verify:
            sha256 = self.compute_sha256()
            if sha256 != self.sha256:
                logger.info('%s contents updated to %s', self.filename, sha256)

                if not any(modified.values()):
                    logger.fatal('possible data corruption on %s, contents changed without metadata change!', self.filename)
                    logger.error('manual investigation required, not updating database')
                    return False

                self.sha256 = sha256
                return True
            else:
                logger.info('%s detected as updated but contents unchanged', self)

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


##########################
##### History object #####
##########################

class MSHistory(object):
    __tablename__ = 'history'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("files.id"), nullable=False)
    field = Column(String(64), nullable=False)
    value = Column(String(256), nullable=False)
    timestamp = Column(DateTime, nullable=False)

    def __init__(self, msfile, field, value, status='update', ts=datetime.now()):
        self.file_id = msfile.id
        self.field = field
        self.value = value
        self.status = status
        self.timestamp = ts


##########################
##### Manager object #####
##########################

class MSManager(object):

    def __init__(self):
        pass

    # Namespace reasons, for the moment...
    #def init(self, db, path, update, verify_all, strong_verify, dedup):
    def init(self, db, options):
        logger.info('initializing database')
        engine = create_engine('sqlite:///%s' % db)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        self.sasession = Session()

        logger.info('reading file data from database')
        self.existing_files = self.sasession.query(MSFile).all()
        # TODO: load ignore list from db
        self.ignored_files = list()
        self.missing_files = list()

        # TODO: make into some sort of options/args dict? (don't clutter global namespace)
        #self.path = path
        #self.update = update
        #self.strong_verify = strong_verify
        #self.verify_all = verify_all
        #self.dedup = dedup
        self.options = options

        # Reconcile the DB data with on-disk bytes
        self.verify_files()


    def create_temp_files(self):
        logger.info('creating temp files')
        import tempfile
        #fn = os.path.join(self.path, uuid.uuid4())
        (tmpfile, tmpfn) = tempfile.mkstemp(dir=self.options['path'])
        os.write(tmpfile, os.urandom(1024))
        os.close(tmpfile)
        logger.debug('created %s', tmpfn)
        self.add_file(tmpfn)
        os.unlink(tmpfn)

        (tmpfile, tmpfn) = tempfile.mkstemp(dir=self.options['path'])
        os.write(tmpfile, os.urandom(1024))
        os.close(tmpfile)
        logger.debug('created %s', tmpfn)
        self.add_file(tmpfn)
        if not os.path.exists(os.path.join(self.options['path'], 'tmpdir')):
            tmp_path = os.mkdir(os.path.join(self.options['path'], 'tmpdir'))
        import shutil
        shutil.move(tmpfn, os.path.join(self.options['path'], 'tmpdir'))


    ### Verify internal list of known files ###
    def verify_files(self):
        if len(self.existing_files) == 0:
            logger.info('database new or empty, skipping verification')
            return

        logger.info('verifying database')
        # TODO: handle option where we don't assume recursion
        verify_files = filter(lambda x: self.options['path'] in x.file_path or self.options['verify_all'], self.existing_files)
        logger.info('%d total files found, %d to be scanned', len(self.existing_files), len(verify_files))
        files_scanned = 0

        for msfile in verify_files:
            logger.debug('visiting [%d/%d] %s', files_scanned+1, len(verify_files), msfile.filename)
            try:
                result = msfile.visit(self.options['strong_verify'])
            # Mark files as missing but do not commit to DB yet
            except FileMissingError:
                result = False
                msfile.status = 'missing'
                self.missing_files.append(msfile)

            if result:
                self.sasession.add(msfile)
                self.sasession.commit()

            files_scanned += 1

        # TODO: do something with missing_files
        if len(self.missing_files) == 0:
            logger.info('verification completed, all files accounted for')
        else:
            logger.info('verification completed, %d files missing', len(self.missing_files))


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

            for name in files:
                if files_parsed % 10 == 0 and files_parsed > 0:
                    logger.info('status: %d skipped, %d new, %d parsed, %d total', files_skipped, len(new_files), files_parsed, total_files)

                filename = os.path.join(root, name)
                logger.info('checking [%d/%d]: %s', files_parsed+1, total_files, filename)

                existing_file = self.get_file_db(filename)
                if existing_file:
                    # TODO: files being visited twice, once on init with verify_db, and then now
                    # Fix by commenting out visit below()
                    # existing_file.visit()
                    logger.info('file exists, skipping')
                    files_skipped += 1
                else:
                    logger.info('file is new, marking for addition')
                    new_files.append(filename)

                files_parsed += 1

        if new_files:
            logger.info('%d new files found, adding to database', len(new_files))

        for filename in new_files:
            # TODO: reconcile with self.missing
            # TODO: support dedup by comparing metadata against existing files
            if self.check_file_eligable(filename):
                self.add_file(filename, delay_commit=True)

        self.sasession.commit()


    ### Add a file to DB ###
    def add_file(self, filepath, delay_commit=False):
        #logger.debug('adding new file at %s', filepath)
        new_file = MSFile(filepath)
        logger.info('added %s', new_file)
        self.sasession.add(new_file)
        if not delay_commit:
            self.sasession.commit()
        self.existing_files.append(new_file)


    ### Check to see if file exists in DB ###
    def get_file_db(self, file_path):
        # TODO: Do we scan DB directly instead of self.existing_files?
        filtered_files = sorted(filter(lambda x: x.filename == file_path, self.existing_files), key=lambda y: y.added_time)
        if len(filtered_files) == 0:
            return None
        elif len(filtered_files) == 1:
            pass
        else:
            logger.error('multiple files returned on match for %s, returning most recent:', file_path)
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
