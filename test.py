import tempfile
import logging
import shutil
import sys
import os
import re

import click
from click.testing import CliRunner

from metasync import MSManager


# Constants #
TEST_DB = 'test.db'
TEST_LOG = 'test.log'


# Load metasync wrapper
@click.command()
@click.option('--db')
@click.option('--path')
@click.option('--dedup', default=False, type=bool)
def metasync(db, path, dedup):
    mgr = MSManager()
    options = {'path': path, 'dedup': dedup}
    logger.debug('options: %s', options)
    mgr.init(db, options)
    mgr.scan_path()
    sys.exit(0)


#
# Configure app logging to file (to read from later)
# Create mock data files
#
def setup_func(runner):
    test_log_path = os.path.join(os.getcwd(), TEST_LOG)
    app_log = logging.getLogger('metasync')
    fh = logging.FileHandler(test_log_path)
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    app_log.addHandler(fh)

    test_db_path = os.path.join(os.getcwd(), TEST_DB)
    test_data_path = os.path.join(os.getcwd(), 'files')
    logger.debug('creating mock file data')
    if not os.path.exists(test_data_path):
        os.mkdir(test_data_path)
    (test_file, test_file_path) = tempfile.mkstemp(dir=test_data_path)
    os.write(test_file, os.urandom(1024))
    os.close(test_file)

    logger.debug('loading metasync')
    result = runner.invoke(metasync, ['--db', test_db_path, '--path', test_data_path])
    logger.debug('result: %s', result)
    assert result.exit_code == 0
    assert not any(map(lambda x: x in result.output, ['WARNING', 'ERROR', 'CRITICAL']))

    return (test_log_path, test_db_path, test_data_path, test_file_path)


#
# First test #
#
# Test missing file detection:
#  - Create new temp file in "path", add to DB, then remove
#
def test_detect_missing_files():
    logger.info('running detect_missing_files test')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_log_path, test_db_path, test_data_path, test_file_path) = setup_func(runner)

        # Do our test operation
        logger.debug('removing mock file')
        os.unlink(test_file_path)

        # Test successful detection
        logger.debug('reloading metasync')
        result = runner.invoke(metasync, ['--db', test_db_path, '--path', test_data_path])
        with open(test_log_path, 'r') as log_file_h:
            test_log_data = ''.join(log_file_h.readlines())
        logger.debug('result: %s', result)

        file_missing_msg = 'WARNING - %s missing' % test_file_path
        #logger.debug('searching for message: %s', file_missing_msg)
        assert result.exit_code == 0
        assert not any(map(lambda x: x in test_log_data, ['ERROR', 'CRITICAL']))
        assert file_missing_msg in test_log_data
        logger.info('test passed')


#
# Second test #
#
# Test moved file detection:
#  - Create new temp file in "path", then create subfolder, move temp file
#
def test_detect_moved_files():
    logger.info('running detect_moved_file test')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_log_path, test_db_path, test_data_path, test_file_path) = setup_func(runner)

        # Do our test operation
        tmp_path = os.path.join(test_data_path, 'tmpdir')
        new_test_file_path = os.path.join(tmp_path, os.path.basename(test_file_path))
        logger.debug('creating new temporary directory %s', tmp_path)
        if not os.path.exists(tmp_path):
            os.mkdir(tmp_path)
        logger.debug('moving %s to %s', test_file_path, new_test_file_path)
        shutil.move(test_file_path, new_test_file_path)

        # Test successful detection
        logger.debug('reloading metasync')
        result = runner.invoke(metasync, ['--db', test_db_path, '--path', test_data_path])
        with open(test_log_path, 'r') as log_file_h:
            test_log_data = ''.join(log_file_h.readlines())
        logger.debug('result: %s', result)

        file_missing_msg = 'WARNING - %s missing' % test_file_path
        match_found_msg = '^.*match on .*%s.* found with .*%s.*$' % (test_file_path, new_test_file_path)
        update_file_msg = '^.*updating missing file .*%s.* to match new .*%s.*$' % (test_file_path, new_test_file_path)
        match_found_re = re.compile(match_found_msg, re.M)
        update_file_re = re.compile(match_found_msg, re.M)
        #logger.debug('searching for message: %s', file_missing_msg)
        #logger.debug('searching for message: %s', match_found_msg)
        #logger.debug('test log data: %s', test_log_data)
        assert result.exit_code == 0
        assert not any(map(lambda x: x in test_log_data, ['ERROR', 'CRITICAL']))
        assert file_missing_msg in test_log_data
        assert re.search(match_found_re, test_log_data)
        assert re.search(update_file_re, test_log_data)
        logger.info('test passed')


#
# Third test
#
# Dedupe functionality:
#  - Create new temp file in "path", copy to new temp file in same path
#
def test_create_dupe_files():
    logger.info('running create_dupe_files test')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_log_path, test_db_path, test_data_path, test_file_path) = setup_func(runner)

        # Do our test operation
        (test_file2, test_file2_path) = tempfile.mkstemp(dir=test_data_path)
        os.close(test_file2)
        logger.debug('created %s, copying to %s', test_file_path, test_file2_path)
        shutil.copy(test_file_path, test_file2_path)

        # Test successful detection
        logger.debug('reloading metasync')
        result = runner.invoke(metasync, ['--db', test_db_path, '--path', test_data_path, '--dedup', True])
        with open(test_log_path, 'r') as log_file_h:
            test_log_data = ''.join(log_file_h.readlines())
        logger.debug('result: %s', result)

        new_dupe_msg = '^.*new file:.*%s.*$' % (test_file2_path)
        existing_dupe_msg = '^.*existing file:.*%s.*$' % (test_file_path)
        new_dupe_re = re.compile(new_dupe_msg, re.M)
        existing_dupe_re = re.compile(existing_dupe_msg, re.M)
        #logger.debug('searching for message: %s', file_missing_msg)
        #logger.debug('searching for message: %s', match_found_msg)
        #logger.debug('test log data: %s', test_log_data)
        assert result.exit_code == 0
        assert not any(map(lambda x: x in test_log_data, ['ERROR', 'CRITICAL']))
        assert 'duplicate file detected' in test_log_data
        assert re.search(new_dupe_re, test_log_data)
        assert re.search(existing_dupe_re, test_log_data)
        logger.info('test passed')



# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


if __name__ == '__main__':
    test_detect_missing_files()
    test_detect_moved_files()
    test_create_dupe_files()

